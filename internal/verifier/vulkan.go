package verifier

import (
	"errors"
	"fmt"
	"io/ioutil"
	"math"
	"unsafe"

	vk "github.com/vulkan-go/vulkan"
)

const (
	// Maximum password length supported by GPU
	MaxPasswordLength = 256
	// Default batch size for GPU processing
	DefaultGPUBatchSize = 4096
)

// vulkanVerifier implements the Verifier interface using Vulkan compute shaders
type vulkanVerifier struct {
	instance       vk.Instance
	physicalDevice vk.PhysicalDevice
	device         vk.Device
	queue          vk.Queue
	commandPool    vk.CommandPool
	descriptorPool vk.DescriptorPool

	// Compute pipeline
	computePipeline     vk.Pipeline
	pipelineLayout      vk.PipelineLayout
	descriptorSetLayout vk.DescriptorSetLayout

	// Memory properties
	memoryProperties vk.PhysicalDeviceMemoryProperties
}

// vulkanWorker represents a per-goroutine worker that processes batches on the GPU
type vulkanWorker struct {
	verifier  *vulkanVerifier
	zipInfo   *ZipCryptoInfo
	batchSize int

	// Vulkan resources for this worker
	descriptorSet vk.DescriptorSet
	commandBuffer vk.CommandBuffer

	// Buffers
	passwordLengthsBuffer vk.Buffer
	passwordLengthsMemory vk.DeviceMemory
	passwordDataBuffer    vk.Buffer
	passwordDataMemory    vk.DeviceMemory
	zipHeaderBuffer       vk.Buffer
	zipHeaderMemory       vk.DeviceMemory
	resultsBuffer         vk.Buffer
	resultsMemory         vk.DeviceMemory
}

// NewVulkan creates a new Vulkan-based verifier
func NewVulkan() (Verifier, error) {
	// Initialize Vulkan with better error handling
	if err := vk.SetDefaultGetInstanceProcAddr(); err != nil {
		return nil, fmt.Errorf("failed to set Vulkan loader: %w", err)
	}

	if err := vk.Init(); err != nil {
		return nil, fmt.Errorf("failed to initialize Vulkan (ensure Vulkan SDK is installed and GPU drivers are up to date): %w", err)
	}

	v := &vulkanVerifier{}

	// Create instance
	if err := v.createInstance(); err != nil {
		return nil, fmt.Errorf("failed to create Vulkan instance: %w", err)
	}

	// Select physical device
	if err := v.selectPhysicalDevice(); err != nil {
		v.cleanup()
		return nil, fmt.Errorf("failed to select physical device: %w", err)
	}

	// Create logical device
	if err := v.createDevice(); err != nil {
		v.cleanup()
		return nil, fmt.Errorf("failed to create device: %w", err)
	}

	// Create command pool
	if err := v.createCommandPool(); err != nil {
		v.cleanup()
		return nil, fmt.Errorf("failed to create command pool: %w", err)
	}

	// Load and create compute pipeline
	if err := v.createComputePipeline(); err != nil {
		v.cleanup()
		return nil, fmt.Errorf("failed to create compute pipeline: %w", err)
	}

	// Create descriptor pool
	if err := v.createDescriptorPool(); err != nil {
		v.cleanup()
		return nil, fmt.Errorf("failed to create descriptor pool: %w", err)
	}

	return v, nil
}

func (v *vulkanVerifier) NewWorker(zipBytes []byte) (Worker, error) {
	// Parse ZIP headers to extract ZipCrypto info
	zipInfo, err := parseZipHeaders(zipBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ZIP headers: %w", err)
	}

	worker := &vulkanWorker{
		verifier:  v,
		zipInfo:   zipInfo,
		batchSize: DefaultGPUBatchSize,
	}

	// Create buffers and descriptor set for this worker
	if err := worker.createBuffers(); err != nil {
		return nil, fmt.Errorf("failed to create worker buffers: %w", err)
	}

	if err := worker.createDescriptorSet(); err != nil {
		worker.cleanup()
		return nil, fmt.Errorf("failed to create descriptor set: %w", err)
	}

	if err := worker.createCommandBuffer(); err != nil {
		worker.cleanup()
		return nil, fmt.Errorf("failed to create command buffer: %w", err)
	}

	return worker, nil
}

// BatchVerify processes a batch of passwords on the GPU
func (w *vulkanWorker) BatchVerify(batch []string) (int, int) {
	if len(batch) == 0 {
		return -1, 0
	}

	// Ensure batch doesn't exceed our allocated size
	batchLen := len(batch)
	if batchLen > w.batchSize {
		batchLen = w.batchSize
		batch = batch[:batchLen]
	}

	// Upload password data to GPU
	if err := w.uploadPasswordData(batch); err != nil {
		return -1, len(batch) // Fallback to CPU count
	}

	// Dispatch compute shader
	if err := w.dispatchCompute(batchLen); err != nil {
		return -1, len(batch)
	}

	// Download and check results
	matchIndex := w.downloadResults(batchLen)
	return matchIndex, len(batch)
}

func (w *vulkanWorker) Close() {
	w.cleanup()
}

// Vulkan initialization methods
func (v *vulkanVerifier) createInstance() error {
	appInfo := &vk.ApplicationInfo{
		SType:              vk.StructureTypeApplicationInfo,
		PApplicationName:   "ZipCrack",
		ApplicationVersion: vk.MakeVersion(1, 0, 0),
		PEngineName:        "ZipCrack Engine",
		EngineVersion:      vk.MakeVersion(1, 0, 0),
		ApiVersion:         vk.ApiVersion10,
	}

	instanceCreateInfo := &vk.InstanceCreateInfo{
		SType:            vk.StructureTypeInstanceCreateInfo,
		PApplicationInfo: appInfo,
	}

	var instance vk.Instance
	if ret := vk.CreateInstance(instanceCreateInfo, nil, &instance); ret != vk.Success {
		return fmt.Errorf("failed to create instance: %s", ret)
	}

	v.instance = instance
	return nil
}

func (v *vulkanVerifier) selectPhysicalDevice() error {
	var deviceCount uint32
	if ret := vk.EnumeratePhysicalDevices(v.instance, &deviceCount, nil); ret != vk.Success {
		return fmt.Errorf("failed to enumerate devices: %s", ret)
	}

	if deviceCount == 0 {
		return errors.New("no Vulkan devices found")
	}

	devices := make([]vk.PhysicalDevice, deviceCount)
	if ret := vk.EnumeratePhysicalDevices(v.instance, &deviceCount, devices); ret != vk.Success {
		return fmt.Errorf("failed to get devices: %s", ret)
	}

	// Select the first suitable device (could be improved with scoring)
	for _, device := range devices {
		var properties vk.PhysicalDeviceProperties
		vk.GetPhysicalDeviceProperties(device, &properties)
		properties.Deref()

		// Check if device supports compute
		var queueFamilyCount uint32
		vk.GetPhysicalDeviceQueueFamilyProperties(device, &queueFamilyCount, nil)

		queueFamilies := make([]vk.QueueFamilyProperties, queueFamilyCount)
		vk.GetPhysicalDeviceQueueFamilyProperties(device, &queueFamilyCount, queueFamilies)

		for _, queueFamily := range queueFamilies {
			queueFamily.Deref()
			if (queueFamily.QueueFlags & vk.QueueFlags(vk.QueueComputeBit)) != 0 {
				v.physicalDevice = device
				vk.GetPhysicalDeviceMemoryProperties(device, &v.memoryProperties)
				v.memoryProperties.Deref()
				return nil
			}
		}
	}

	return errors.New("no suitable device found")
}

func (v *vulkanVerifier) createDevice() error {
	// Find compute queue family
	var queueFamilyCount uint32
	vk.GetPhysicalDeviceQueueFamilyProperties(v.physicalDevice, &queueFamilyCount, nil)

	queueFamilies := make([]vk.QueueFamilyProperties, queueFamilyCount)
	vk.GetPhysicalDeviceQueueFamilyProperties(v.physicalDevice, &queueFamilyCount, queueFamilies)

	computeQueueFamily := uint32(math.MaxUint32)
	for i, queueFamily := range queueFamilies {
		queueFamily.Deref()
		if (queueFamily.QueueFlags & vk.QueueFlags(vk.QueueComputeBit)) != 0 {
			computeQueueFamily = uint32(i)
			break
		}
	}

	if computeQueueFamily == math.MaxUint32 {
		return errors.New("no compute queue family found")
	}

	queuePriority := float32(1.0)
	queueCreateInfo := &vk.DeviceQueueCreateInfo{
		SType:            vk.StructureTypeDeviceQueueCreateInfo,
		QueueFamilyIndex: computeQueueFamily,
		QueueCount:       1,
		PQueuePriorities: []float32{queuePriority},
	}

	deviceCreateInfo := &vk.DeviceCreateInfo{
		SType:                vk.StructureTypeDeviceCreateInfo,
		QueueCreateInfoCount: 1,
		PQueueCreateInfos:    []vk.DeviceQueueCreateInfo{*queueCreateInfo},
	}

	var device vk.Device
	if ret := vk.CreateDevice(v.physicalDevice, deviceCreateInfo, nil, &device); ret != vk.Success {
		return fmt.Errorf("failed to create device: %s", ret)
	}

	v.device = device

	// Get queue handle
	var queue vk.Queue
	vk.GetDeviceQueue(device, computeQueueFamily, 0, &queue)
	v.queue = queue

	return nil
}

func (v *vulkanVerifier) createCommandPool() error {
	// Find compute queue family index again
	var queueFamilyCount uint32
	vk.GetPhysicalDeviceQueueFamilyProperties(v.physicalDevice, &queueFamilyCount, nil)

	queueFamilies := make([]vk.QueueFamilyProperties, queueFamilyCount)
	vk.GetPhysicalDeviceQueueFamilyProperties(v.physicalDevice, &queueFamilyCount, queueFamilies)

	computeQueueFamily := uint32(0)
	for i, queueFamily := range queueFamilies {
		queueFamily.Deref()
		if (queueFamily.QueueFlags & vk.QueueFlags(vk.QueueComputeBit)) != 0 {
			computeQueueFamily = uint32(i)
			break
		}
	}

	poolCreateInfo := &vk.CommandPoolCreateInfo{
		SType:            vk.StructureTypeCommandPoolCreateInfo,
		Flags:            vk.CommandPoolCreateFlags(vk.CommandPoolCreateResetCommandBufferBit),
		QueueFamilyIndex: computeQueueFamily,
	}

	var commandPool vk.CommandPool
	if ret := vk.CreateCommandPool(v.device, poolCreateInfo, nil, &commandPool); ret != vk.Success {
		return fmt.Errorf("failed to create command pool: %s", ret)
	}

	v.commandPool = commandPool
	return nil
}

func (v *vulkanVerifier) createComputePipeline() error {
	// Load SPIR-V shader
	shaderCode, err := ioutil.ReadFile("shaders/zipcrack.spv")
	if err != nil {
		return fmt.Errorf("failed to read shader file: %w", err)
	}

	// Create shader module
	shaderCreateInfo := &vk.ShaderModuleCreateInfo{
		SType:    vk.StructureTypeShaderModuleCreateInfo,
		CodeSize: uint(len(shaderCode)),
		PCode:    reinterpretAsUint32Slice(shaderCode),
	}

	var shaderModule vk.ShaderModule
	if ret := vk.CreateShaderModule(v.device, shaderCreateInfo, nil, &shaderModule); ret != vk.Success {
		return fmt.Errorf("failed to create shader module: %s", ret)
	}
	defer vk.DestroyShaderModule(v.device, shaderModule, nil)

	// Create descriptor set layout
	bindings := []vk.DescriptorSetLayoutBinding{
		{
			Binding:         0,
			DescriptorType:  vk.DescriptorTypeStorageBuffer,
			DescriptorCount: 1,
			StageFlags:      vk.ShaderStageFlags(vk.ShaderStageComputeBit),
		},
		{
			Binding:         1,
			DescriptorType:  vk.DescriptorTypeStorageBuffer,
			DescriptorCount: 1,
			StageFlags:      vk.ShaderStageFlags(vk.ShaderStageComputeBit),
		},
		{
			Binding:         2,
			DescriptorType:  vk.DescriptorTypeStorageBuffer,
			DescriptorCount: 1,
			StageFlags:      vk.ShaderStageFlags(vk.ShaderStageComputeBit),
		},
		{
			Binding:         3,
			DescriptorType:  vk.DescriptorTypeStorageBuffer,
			DescriptorCount: 1,
			StageFlags:      vk.ShaderStageFlags(vk.ShaderStageComputeBit),
		},
	}

	layoutCreateInfo := &vk.DescriptorSetLayoutCreateInfo{
		SType:        vk.StructureTypeDescriptorSetLayoutCreateInfo,
		BindingCount: uint32(len(bindings)),
		PBindings:    bindings,
	}

	var descriptorSetLayout vk.DescriptorSetLayout
	if ret := vk.CreateDescriptorSetLayout(v.device, layoutCreateInfo, nil, &descriptorSetLayout); ret != vk.Success {
		return fmt.Errorf("failed to create descriptor set layout: %s", ret)
	}
	v.descriptorSetLayout = descriptorSetLayout

	// Create pipeline layout
	pipelineLayoutCreateInfo := &vk.PipelineLayoutCreateInfo{
		SType:          vk.StructureTypePipelineLayoutCreateInfo,
		SetLayoutCount: 1,
		PSetLayouts:    []vk.DescriptorSetLayout{descriptorSetLayout},
	}

	var pipelineLayout vk.PipelineLayout
	if ret := vk.CreatePipelineLayout(v.device, pipelineLayoutCreateInfo, nil, &pipelineLayout); ret != vk.Success {
		return fmt.Errorf("failed to create pipeline layout: %s", ret)
	}
	v.pipelineLayout = pipelineLayout

	// Create compute pipeline
	stageCreateInfo := &vk.PipelineShaderStageCreateInfo{
		SType:  vk.StructureTypePipelineShaderStageCreateInfo,
		Stage:  vk.ShaderStageFlagBits(vk.ShaderStageComputeBit),
		Module: shaderModule,
		PName:  "main\x00",
	}

	pipelineCreateInfo := &vk.ComputePipelineCreateInfo{
		SType:  vk.StructureTypeComputePipelineCreateInfo,
		Stage:  *stageCreateInfo,
		Layout: pipelineLayout,
	}

	var pipeline vk.Pipeline
	if ret := vk.CreateComputePipelines(v.device, vk.PipelineCache(vk.NullHandle), 1, []vk.ComputePipelineCreateInfo{*pipelineCreateInfo}, nil, []vk.Pipeline{pipeline}); ret != vk.Success {
		return fmt.Errorf("failed to create compute pipeline: %s", ret)
	}
	v.computePipeline = pipeline

	return nil
}

func (v *vulkanVerifier) createDescriptorPool() error {
	poolSizes := []vk.DescriptorPoolSize{
		{
			Type:            vk.DescriptorTypeStorageBuffer,
			DescriptorCount: 1000, // Allow for many workers
		},
	}

	poolCreateInfo := &vk.DescriptorPoolCreateInfo{
		SType:         vk.StructureTypeDescriptorPoolCreateInfo,
		Flags:         vk.DescriptorPoolCreateFlags(vk.DescriptorPoolCreateFreeDescriptorSetBit),
		MaxSets:       1000,
		PoolSizeCount: uint32(len(poolSizes)),
		PPoolSizes:    poolSizes,
	}

	var descriptorPool vk.DescriptorPool
	if ret := vk.CreateDescriptorPool(v.device, poolCreateInfo, nil, &descriptorPool); ret != vk.Success {
		return fmt.Errorf("failed to create descriptor pool: %s", ret)
	}

	v.descriptorPool = descriptorPool
	return nil
}

// Worker buffer management
func (w *vulkanWorker) createBuffers() error {
	// Calculate buffer sizes
	passwordLengthsSize := uint64(w.batchSize * 4)              // uint32 per password
	passwordDataSize := uint64(w.batchSize * MaxPasswordLength) // Worst case: max length per password
	zipHeaderSize := uint64(32)                                 // 12 bytes header + 4 bytes check byte + padding
	resultsSize := uint64(w.batchSize * 4)                      // uint32 per result

	// Create buffers
	if err := w.createBuffer(passwordLengthsSize, vk.BufferUsageFlags(vk.BufferUsageStorageBufferBit),
		vk.MemoryPropertyFlags(vk.MemoryPropertyHostVisibleBit|vk.MemoryPropertyHostCoherentBit),
		&w.passwordLengthsBuffer, &w.passwordLengthsMemory); err != nil {
		return fmt.Errorf("failed to create password lengths buffer: %w", err)
	}

	if err := w.createBuffer(passwordDataSize, vk.BufferUsageFlags(vk.BufferUsageStorageBufferBit),
		vk.MemoryPropertyFlags(vk.MemoryPropertyHostVisibleBit|vk.MemoryPropertyHostCoherentBit),
		&w.passwordDataBuffer, &w.passwordDataMemory); err != nil {
		return fmt.Errorf("failed to create password data buffer: %w", err)
	}

	if err := w.createBuffer(zipHeaderSize, vk.BufferUsageFlags(vk.BufferUsageStorageBufferBit),
		vk.MemoryPropertyFlags(vk.MemoryPropertyHostVisibleBit|vk.MemoryPropertyHostCoherentBit),
		&w.zipHeaderBuffer, &w.zipHeaderMemory); err != nil {
		return fmt.Errorf("failed to create zip header buffer: %w", err)
	}

	if err := w.createBuffer(resultsSize, vk.BufferUsageFlags(vk.BufferUsageStorageBufferBit),
		vk.MemoryPropertyFlags(vk.MemoryPropertyHostVisibleBit|vk.MemoryPropertyHostCoherentBit),
		&w.resultsBuffer, &w.resultsMemory); err != nil {
		return fmt.Errorf("failed to create results buffer: %w", err)
	}

	// Upload ZIP header data (constant for this worker)
	return w.uploadZipHeader()
}

func (w *vulkanWorker) createBuffer(size uint64, usage vk.BufferUsageFlags, properties vk.MemoryPropertyFlags, buffer *vk.Buffer, memory *vk.DeviceMemory) error {
	bufferCreateInfo := &vk.BufferCreateInfo{
		SType: vk.StructureTypeBufferCreateInfo,
		Size:  vk.DeviceSize(size),
		Usage: usage,
	}

	if ret := vk.CreateBuffer(w.verifier.device, bufferCreateInfo, nil, buffer); ret != vk.Success {
		return fmt.Errorf("failed to create buffer: %s", ret)
	}

	var memRequirements vk.MemoryRequirements
	vk.GetBufferMemoryRequirements(w.verifier.device, *buffer, &memRequirements)
	memRequirements.Deref()

	memTypeIndex := w.findMemoryType(memRequirements.MemoryTypeBits, properties)
	if memTypeIndex == math.MaxUint32 {
		return errors.New("failed to find suitable memory type")
	}

	allocInfo := &vk.MemoryAllocateInfo{
		SType:           vk.StructureTypeMemoryAllocateInfo,
		AllocationSize:  memRequirements.Size,
		MemoryTypeIndex: memTypeIndex,
	}

	if ret := vk.AllocateMemory(w.verifier.device, allocInfo, nil, memory); ret != vk.Success {
		return fmt.Errorf("failed to allocate memory: %s", ret)
	}

	if ret := vk.BindBufferMemory(w.verifier.device, *buffer, *memory, 0); ret != vk.Success {
		return fmt.Errorf("failed to bind buffer memory: %s", ret)
	}

	return nil
}

func (w *vulkanWorker) findMemoryType(typeFilter uint32, properties vk.MemoryPropertyFlags) uint32 {
	w.verifier.memoryProperties.Deref()
	for i := uint32(0); i < w.verifier.memoryProperties.MemoryTypeCount; i++ {
		if (typeFilter&(1<<i)) != 0 && (w.verifier.memoryProperties.MemoryTypes[i].PropertyFlags&properties) == properties {
			return i
		}
	}
	return math.MaxUint32
}

// Helper methods
func (w *vulkanWorker) uploadZipHeader() error {
	headerData := struct {
		EncryptedHeader [3]uint32
		CheckByte       uint32
		Padding         [3]uint32
	}{
		CheckByte: uint32(w.zipInfo.CheckByte),
	}

	// Pack 12-byte header into 3 uint32s
	for i := 0; i < 12; i += 4 {
		headerData.EncryptedHeader[i/4] = uint32(w.zipInfo.EncryptedHeader[i]) |
			uint32(w.zipInfo.EncryptedHeader[i+1])<<8 |
			uint32(w.zipInfo.EncryptedHeader[i+2])<<16 |
			uint32(w.zipInfo.EncryptedHeader[i+3])<<24
	}

	return w.writeToBuffer(w.zipHeaderMemory, unsafe.Pointer(&headerData), unsafe.Sizeof(headerData))
}

func (w *vulkanWorker) uploadPasswordData(batch []string) error {
	// Upload password lengths
	lengths := make([]uint32, w.batchSize)
	for i, password := range batch {
		if i >= w.batchSize {
			break
		}
		lengths[i] = uint32(len(password))
	}

	if err := w.writeToBuffer(w.passwordLengthsMemory, unsafe.Pointer(&lengths[0]), uintptr(len(lengths)*4)); err != nil {
		return err
	}

	// Pack password data into uint32s
	passwordData := make([]uint32, w.batchSize*MaxPasswordLength/4)
	dataOffset := 0

	for i, password := range batch {
		if i >= w.batchSize {
			break
		}

		passwordBytes := []byte(password)
		wordsNeeded := (len(passwordBytes) + 3) / 4

		for j := 0; j < wordsNeeded; j++ {
			var word uint32
			for k := 0; k < 4 && j*4+k < len(passwordBytes); k++ {
				word |= uint32(passwordBytes[j*4+k]) << (k * 8)
			}
			passwordData[dataOffset] = word
			dataOffset++
		}
	}

	return w.writeToBuffer(w.passwordDataMemory, unsafe.Pointer(&passwordData[0]), uintptr(len(passwordData)*4))
}

func (w *vulkanWorker) writeToBuffer(memory vk.DeviceMemory, data unsafe.Pointer, size uintptr) error {
	var mappedData unsafe.Pointer
	if ret := vk.MapMemory(w.verifier.device, memory, 0, vk.DeviceSize(vk.WholeSize), 0, &mappedData); ret != vk.Success {
		return fmt.Errorf("failed to map memory: %s", ret)
	}
	defer vk.UnmapMemory(w.verifier.device, memory)

	// Copy data byte by byte
	srcBytes := (*[1 << 30]byte)(data)[:size]
	vk.Memcopy(mappedData, srcBytes)
	return nil
}

func (w *vulkanWorker) createDescriptorSet() error {
	allocInfo := &vk.DescriptorSetAllocateInfo{
		SType:              vk.StructureTypeDescriptorSetAllocateInfo,
		DescriptorPool:     w.verifier.descriptorPool,
		DescriptorSetCount: 1,
		PSetLayouts:        []vk.DescriptorSetLayout{w.verifier.descriptorSetLayout},
	}

	var descriptorSet vk.DescriptorSet
	if ret := vk.AllocateDescriptorSets(w.verifier.device, allocInfo, &descriptorSet); ret != vk.Success {
		return fmt.Errorf("failed to allocate descriptor sets: %s", ret)
	}
	w.descriptorSet = descriptorSet

	// Update descriptor sets
	descriptorWrites := []vk.WriteDescriptorSet{
		{
			SType:           vk.StructureTypeWriteDescriptorSet,
			DstSet:          w.descriptorSet,
			DstBinding:      0,
			DstArrayElement: 0,
			DescriptorType:  vk.DescriptorTypeStorageBuffer,
			DescriptorCount: 1,
			PBufferInfo: []vk.DescriptorBufferInfo{{
				Buffer: w.passwordLengthsBuffer,
				Offset: 0,
				Range:  vk.DeviceSize(vk.WholeSize),
			}},
		},
		{
			SType:           vk.StructureTypeWriteDescriptorSet,
			DstSet:          w.descriptorSet,
			DstBinding:      1,
			DstArrayElement: 0,
			DescriptorType:  vk.DescriptorTypeStorageBuffer,
			DescriptorCount: 1,
			PBufferInfo: []vk.DescriptorBufferInfo{{
				Buffer: w.passwordDataBuffer,
				Offset: 0,
				Range:  vk.DeviceSize(vk.WholeSize),
			}},
		},
		{
			SType:           vk.StructureTypeWriteDescriptorSet,
			DstSet:          w.descriptorSet,
			DstBinding:      2,
			DstArrayElement: 0,
			DescriptorType:  vk.DescriptorTypeStorageBuffer,
			DescriptorCount: 1,
			PBufferInfo: []vk.DescriptorBufferInfo{{
				Buffer: w.zipHeaderBuffer,
				Offset: 0,
				Range:  vk.DeviceSize(vk.WholeSize),
			}},
		},
		{
			SType:           vk.StructureTypeWriteDescriptorSet,
			DstSet:          w.descriptorSet,
			DstBinding:      3,
			DstArrayElement: 0,
			DescriptorType:  vk.DescriptorTypeStorageBuffer,
			DescriptorCount: 1,
			PBufferInfo: []vk.DescriptorBufferInfo{{
				Buffer: w.resultsBuffer,
				Offset: 0,
				Range:  vk.DeviceSize(vk.WholeSize),
			}},
		},
	}

	vk.UpdateDescriptorSets(w.verifier.device, uint32(len(descriptorWrites)), descriptorWrites, 0, nil)
	return nil
}

func (w *vulkanWorker) createCommandBuffer() error {
	allocInfo := &vk.CommandBufferAllocateInfo{
		SType:              vk.StructureTypeCommandBufferAllocateInfo,
		CommandPool:        w.verifier.commandPool,
		Level:              vk.CommandBufferLevelPrimary,
		CommandBufferCount: 1,
	}

	commandBuffers := make([]vk.CommandBuffer, 1)
	if ret := vk.AllocateCommandBuffers(w.verifier.device, allocInfo, commandBuffers); ret != vk.Success {
		return fmt.Errorf("failed to allocate command buffer: %s", ret)
	}
	w.commandBuffer = commandBuffers[0]

	return nil
}

func (w *vulkanWorker) dispatchCompute(batchSize int) error {
	beginInfo := &vk.CommandBufferBeginInfo{
		SType: vk.StructureTypeCommandBufferBeginInfo,
		Flags: vk.CommandBufferUsageFlags(vk.CommandBufferUsageOneTimeSubmitBit),
	}

	if ret := vk.BeginCommandBuffer(w.commandBuffer, beginInfo); ret != vk.Success {
		return fmt.Errorf("failed to begin command buffer: %s", ret)
	}

	vk.CmdBindPipeline(w.commandBuffer, vk.PipelineBindPointCompute, w.verifier.computePipeline)
	vk.CmdBindDescriptorSets(w.commandBuffer, vk.PipelineBindPointCompute, w.verifier.pipelineLayout, 0, 1, []vk.DescriptorSet{w.descriptorSet}, 0, nil)

	// Dispatch with workgroups of 64 threads each
	groupCount := uint32((batchSize + 63) / 64)
	vk.CmdDispatch(w.commandBuffer, groupCount, 1, 1)

	if ret := vk.EndCommandBuffer(w.commandBuffer); ret != vk.Success {
		return fmt.Errorf("failed to end command buffer: %s", ret)
	}

	// Submit command buffer
	submitInfo := &vk.SubmitInfo{
		SType:              vk.StructureTypeSubmitInfo,
		CommandBufferCount: 1,
		PCommandBuffers:    []vk.CommandBuffer{w.commandBuffer},
	}

	if ret := vk.QueueSubmit(w.verifier.queue, 1, []vk.SubmitInfo{*submitInfo}, vk.NullFence); ret != vk.Success {
		return fmt.Errorf("failed to submit command buffer: %s", ret)
	}

	// Wait for completion
	if ret := vk.QueueWaitIdle(w.verifier.queue); ret != vk.Success {
		return fmt.Errorf("failed to wait for queue: %s", ret)
	}

	return nil
}

func (w *vulkanWorker) downloadResults(batchSize int) int {
	// Map results buffer and read results
	var mappedData unsafe.Pointer
	if ret := vk.MapMemory(w.verifier.device, w.resultsMemory, 0, vk.DeviceSize(vk.WholeSize), 0, &mappedData); ret != vk.Success {
		return -1
	}
	defer vk.UnmapMemory(w.verifier.device, w.resultsMemory)

	results := (*[4096]uint32)(mappedData)[:batchSize]

	// Find first match
	for i, result := range results {
		if result != 0 {
			return i
		}
	}

	return -1
}

func (w *vulkanWorker) cleanup() {
	if w.passwordLengthsBuffer != vk.Buffer(vk.NullHandle) {
		vk.DestroyBuffer(w.verifier.device, w.passwordLengthsBuffer, nil)
	}
	if w.passwordLengthsMemory != vk.DeviceMemory(vk.NullHandle) {
		vk.FreeMemory(w.verifier.device, w.passwordLengthsMemory, nil)
	}
	if w.passwordDataBuffer != vk.Buffer(vk.NullHandle) {
		vk.DestroyBuffer(w.verifier.device, w.passwordDataBuffer, nil)
	}
	if w.passwordDataMemory != vk.DeviceMemory(vk.NullHandle) {
		vk.FreeMemory(w.verifier.device, w.passwordDataMemory, nil)
	}
	if w.zipHeaderBuffer != vk.Buffer(vk.NullHandle) {
		vk.DestroyBuffer(w.verifier.device, w.zipHeaderBuffer, nil)
	}
	if w.zipHeaderMemory != vk.DeviceMemory(vk.NullHandle) {
		vk.FreeMemory(w.verifier.device, w.zipHeaderMemory, nil)
	}
	if w.resultsBuffer != vk.Buffer(vk.NullHandle) {
		vk.DestroyBuffer(w.verifier.device, w.resultsBuffer, nil)
	}
	if w.resultsMemory != vk.DeviceMemory(vk.NullHandle) {
		vk.FreeMemory(w.verifier.device, w.resultsMemory, nil)
	}
	if w.descriptorSet != vk.DescriptorSet(vk.NullHandle) {
		vk.FreeDescriptorSets(w.verifier.device, w.verifier.descriptorPool, 1, &w.descriptorSet)
	}
	if w.commandBuffer != vk.CommandBuffer(vk.NullHandle) {
		commandBuffers := []vk.CommandBuffer{w.commandBuffer}
		vk.FreeCommandBuffers(w.verifier.device, w.verifier.commandPool, 1, commandBuffers)
	}
}

func (v *vulkanVerifier) cleanup() {
	if v.descriptorPool != vk.DescriptorPool(vk.NullHandle) {
		vk.DestroyDescriptorPool(v.device, v.descriptorPool, nil)
	}
	if v.computePipeline != vk.Pipeline(vk.NullHandle) {
		vk.DestroyPipeline(v.device, v.computePipeline, nil)
	}
	if v.pipelineLayout != vk.PipelineLayout(vk.NullHandle) {
		vk.DestroyPipelineLayout(v.device, v.pipelineLayout, nil)
	}
	if v.descriptorSetLayout != vk.DescriptorSetLayout(vk.NullHandle) {
		vk.DestroyDescriptorSetLayout(v.device, v.descriptorSetLayout, nil)
	}
	if v.commandPool != vk.CommandPool(vk.NullHandle) {
		vk.DestroyCommandPool(v.device, v.commandPool, nil)
	}
	if v.device != vk.Device(vk.NullHandle) {
		vk.DestroyDevice(v.device, nil)
	}
	if v.instance != vk.Instance(vk.NullHandle) {
		vk.DestroyInstance(v.instance, nil)
	}
}

// Helper function to reinterpret byte slice as uint32 slice for SPIR-V
func reinterpretAsUint32Slice(data []byte) []uint32 {
	if len(data)%4 != 0 {
		// Pad to 4-byte boundary
		padding := 4 - (len(data) % 4)
		data = append(data, make([]byte, padding)...)
	}

	return (*[1 << 30]uint32)(unsafe.Pointer(&data[0]))[:len(data)/4]
}
