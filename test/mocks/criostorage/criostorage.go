// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/cri-o/cri-o/internal/storage (interfaces: ImageServer,RuntimeServer,StorageTransport)

// Package criostoragemock is a generated GoMock package.
package criostoragemock

import (
	context "context"
	reflect "reflect"

	reference "github.com/containers/image/v5/docker/reference"
	types "github.com/containers/image/v5/types"
	storage "github.com/containers/storage"
	types0 "github.com/containers/storage/types"
	storage0 "github.com/cri-o/cri-o/internal/storage"
	references "github.com/cri-o/cri-o/internal/storage/references"
	gomock "github.com/golang/mock/gomock"
	digest "github.com/opencontainers/go-digest"
)

// MockImageServer is a mock of ImageServer interface.
type MockImageServer struct {
	ctrl     *gomock.Controller
	recorder *MockImageServerMockRecorder
}

// MockImageServerMockRecorder is the mock recorder for MockImageServer.
type MockImageServerMockRecorder struct {
	mock *MockImageServer
}

// NewMockImageServer creates a new mock instance.
func NewMockImageServer(ctrl *gomock.Controller) *MockImageServer {
	mock := &MockImageServer{ctrl: ctrl}
	mock.recorder = &MockImageServerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockImageServer) EXPECT() *MockImageServerMockRecorder {
	return m.recorder
}

// CandidatesForPotentiallyShortImageName mocks base method.
func (m *MockImageServer) CandidatesForPotentiallyShortImageName(arg0 *types.SystemContext, arg1 string) ([]references.RegistryImageReference, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CandidatesForPotentiallyShortImageName", arg0, arg1)
	ret0, _ := ret[0].([]references.RegistryImageReference)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CandidatesForPotentiallyShortImageName indicates an expected call of CandidatesForPotentiallyShortImageName.
func (mr *MockImageServerMockRecorder) CandidatesForPotentiallyShortImageName(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CandidatesForPotentiallyShortImageName", reflect.TypeOf((*MockImageServer)(nil).CandidatesForPotentiallyShortImageName), arg0, arg1)
}

// DeleteImage mocks base method.
func (m *MockImageServer) DeleteImage(arg0 *types.SystemContext, arg1 storage0.StorageImageID) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteImage", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteImage indicates an expected call of DeleteImage.
func (mr *MockImageServerMockRecorder) DeleteImage(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteImage", reflect.TypeOf((*MockImageServer)(nil).DeleteImage), arg0, arg1)
}

// GetStore mocks base method.
func (m *MockImageServer) GetStore() storage.Store {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetStore")
	ret0, _ := ret[0].(storage.Store)
	return ret0
}

// GetStore indicates an expected call of GetStore.
func (mr *MockImageServerMockRecorder) GetStore() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetStore", reflect.TypeOf((*MockImageServer)(nil).GetStore))
}

// HeuristicallyTryResolvingStringAsIDPrefix mocks base method.
func (m *MockImageServer) HeuristicallyTryResolvingStringAsIDPrefix(arg0 string) *storage0.StorageImageID {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "HeuristicallyTryResolvingStringAsIDPrefix", arg0)
	ret0, _ := ret[0].(*storage0.StorageImageID)
	return ret0
}

// HeuristicallyTryResolvingStringAsIDPrefix indicates an expected call of HeuristicallyTryResolvingStringAsIDPrefix.
func (mr *MockImageServerMockRecorder) HeuristicallyTryResolvingStringAsIDPrefix(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "HeuristicallyTryResolvingStringAsIDPrefix", reflect.TypeOf((*MockImageServer)(nil).HeuristicallyTryResolvingStringAsIDPrefix), arg0)
}

// ImageStatusByID mocks base method.
func (m *MockImageServer) ImageStatusByID(arg0 *types.SystemContext, arg1 storage0.StorageImageID) (*storage0.ImageResult, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ImageStatusByID", arg0, arg1)
	ret0, _ := ret[0].(*storage0.ImageResult)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ImageStatusByID indicates an expected call of ImageStatusByID.
func (mr *MockImageServerMockRecorder) ImageStatusByID(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ImageStatusByID", reflect.TypeOf((*MockImageServer)(nil).ImageStatusByID), arg0, arg1)
}

// ImageStatusByName mocks base method.
func (m *MockImageServer) ImageStatusByName(arg0 *types.SystemContext, arg1 references.RegistryImageReference) (*storage0.ImageResult, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ImageStatusByName", arg0, arg1)
	ret0, _ := ret[0].(*storage0.ImageResult)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ImageStatusByName indicates an expected call of ImageStatusByName.
func (mr *MockImageServerMockRecorder) ImageStatusByName(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ImageStatusByName", reflect.TypeOf((*MockImageServer)(nil).ImageStatusByName), arg0, arg1)
}

// IsRunningImageAllowed mocks base method.
func (m *MockImageServer) IsRunningImageAllowed(arg0 context.Context, arg1 *types.SystemContext, arg2 references.RegistryImageReference, arg3 digest.Digest) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IsRunningImageAllowed", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(error)
	return ret0
}

// IsRunningImageAllowed indicates an expected call of IsRunningImageAllowed.
func (mr *MockImageServerMockRecorder) IsRunningImageAllowed(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsRunningImageAllowed", reflect.TypeOf((*MockImageServer)(nil).IsRunningImageAllowed), arg0, arg1, arg2, arg3)
}

// ListImages mocks base method.
func (m *MockImageServer) ListImages(arg0 *types.SystemContext) ([]storage0.ImageResult, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListImages", arg0)
	ret0, _ := ret[0].([]storage0.ImageResult)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListImages indicates an expected call of ListImages.
func (mr *MockImageServerMockRecorder) ListImages(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListImages", reflect.TypeOf((*MockImageServer)(nil).ListImages), arg0)
}

// PrepareImage mocks base method.
func (m *MockImageServer) PrepareImage(arg0 *types.SystemContext, arg1 references.RegistryImageReference) (types.ImageCloser, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PrepareImage", arg0, arg1)
	ret0, _ := ret[0].(types.ImageCloser)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// PrepareImage indicates an expected call of PrepareImage.
func (mr *MockImageServerMockRecorder) PrepareImage(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PrepareImage", reflect.TypeOf((*MockImageServer)(nil).PrepareImage), arg0, arg1)
}

// PullImage mocks base method.
func (m *MockImageServer) PullImage(arg0 context.Context, arg1 references.RegistryImageReference, arg2 *storage0.ImageCopyOptions) (types.ImageReference, reference.Canonical, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PullImage", arg0, arg1, arg2)
	ret0, _ := ret[0].(types.ImageReference)
	ret1, _ := ret[1].(reference.Canonical)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// PullImage indicates an expected call of PullImage.
func (mr *MockImageServerMockRecorder) PullImage(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PullImage", reflect.TypeOf((*MockImageServer)(nil).PullImage), arg0, arg1, arg2)
}

// UntagImage mocks base method.
func (m *MockImageServer) UntagImage(arg0 *types.SystemContext, arg1 references.RegistryImageReference) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UntagImage", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// UntagImage indicates an expected call of UntagImage.
func (mr *MockImageServerMockRecorder) UntagImage(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UntagImage", reflect.TypeOf((*MockImageServer)(nil).UntagImage), arg0, arg1)
}

// UpdatePinnedImagesList mocks base method.
func (m *MockImageServer) UpdatePinnedImagesList(arg0 []string) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "UpdatePinnedImagesList", arg0)
}

// UpdatePinnedImagesList indicates an expected call of UpdatePinnedImagesList.
func (mr *MockImageServerMockRecorder) UpdatePinnedImagesList(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdatePinnedImagesList", reflect.TypeOf((*MockImageServer)(nil).UpdatePinnedImagesList), arg0)
}

// MockRuntimeServer is a mock of RuntimeServer interface.
type MockRuntimeServer struct {
	ctrl     *gomock.Controller
	recorder *MockRuntimeServerMockRecorder
}

// MockRuntimeServerMockRecorder is the mock recorder for MockRuntimeServer.
type MockRuntimeServerMockRecorder struct {
	mock *MockRuntimeServer
}

// NewMockRuntimeServer creates a new mock instance.
func NewMockRuntimeServer(ctrl *gomock.Controller) *MockRuntimeServer {
	mock := &MockRuntimeServer{ctrl: ctrl}
	mock.recorder = &MockRuntimeServerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockRuntimeServer) EXPECT() *MockRuntimeServerMockRecorder {
	return m.recorder
}

// CreateContainer mocks base method.
func (m *MockRuntimeServer) CreateContainer(arg0 *types.SystemContext, arg1, arg2, arg3 string, arg4 storage0.StorageImageID, arg5, arg6, arg7 string, arg8 uint32, arg9 *types0.IDMappingOptions, arg10 []string, arg11 bool) (storage0.ContainerInfo, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateContainer", arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11)
	ret0, _ := ret[0].(storage0.ContainerInfo)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateContainer indicates an expected call of CreateContainer.
func (mr *MockRuntimeServerMockRecorder) CreateContainer(arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateContainer", reflect.TypeOf((*MockRuntimeServer)(nil).CreateContainer), arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11)
}

// CreatePodSandbox mocks base method.
func (m *MockRuntimeServer) CreatePodSandbox(arg0 *types.SystemContext, arg1, arg2 string, arg3 references.RegistryImageReference, arg4, arg5, arg6, arg7, arg8 string, arg9 uint32, arg10 *types0.IDMappingOptions, arg11 []string, arg12 bool) (storage0.ContainerInfo, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreatePodSandbox", arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12)
	ret0, _ := ret[0].(storage0.ContainerInfo)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreatePodSandbox indicates an expected call of CreatePodSandbox.
func (mr *MockRuntimeServerMockRecorder) CreatePodSandbox(arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreatePodSandbox", reflect.TypeOf((*MockRuntimeServer)(nil).CreatePodSandbox), arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12)
}

// DeleteContainer mocks base method.
func (m *MockRuntimeServer) DeleteContainer(arg0 context.Context, arg1 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteContainer", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteContainer indicates an expected call of DeleteContainer.
func (mr *MockRuntimeServerMockRecorder) DeleteContainer(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteContainer", reflect.TypeOf((*MockRuntimeServer)(nil).DeleteContainer), arg0, arg1)
}

// GetContainerMetadata mocks base method.
func (m *MockRuntimeServer) GetContainerMetadata(arg0 string) (storage0.RuntimeContainerMetadata, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetContainerMetadata", arg0)
	ret0, _ := ret[0].(storage0.RuntimeContainerMetadata)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetContainerMetadata indicates an expected call of GetContainerMetadata.
func (mr *MockRuntimeServerMockRecorder) GetContainerMetadata(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetContainerMetadata", reflect.TypeOf((*MockRuntimeServer)(nil).GetContainerMetadata), arg0)
}

// GetRunDir mocks base method.
func (m *MockRuntimeServer) GetRunDir(arg0 string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetRunDir", arg0)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetRunDir indicates an expected call of GetRunDir.
func (mr *MockRuntimeServerMockRecorder) GetRunDir(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRunDir", reflect.TypeOf((*MockRuntimeServer)(nil).GetRunDir), arg0)
}

// GetWorkDir mocks base method.
func (m *MockRuntimeServer) GetWorkDir(arg0 string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetWorkDir", arg0)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetWorkDir indicates an expected call of GetWorkDir.
func (mr *MockRuntimeServerMockRecorder) GetWorkDir(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetWorkDir", reflect.TypeOf((*MockRuntimeServer)(nil).GetWorkDir), arg0)
}

// SetContainerMetadata mocks base method.
func (m *MockRuntimeServer) SetContainerMetadata(arg0 string, arg1 *storage0.RuntimeContainerMetadata) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SetContainerMetadata", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// SetContainerMetadata indicates an expected call of SetContainerMetadata.
func (mr *MockRuntimeServerMockRecorder) SetContainerMetadata(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetContainerMetadata", reflect.TypeOf((*MockRuntimeServer)(nil).SetContainerMetadata), arg0, arg1)
}

// StartContainer mocks base method.
func (m *MockRuntimeServer) StartContainer(arg0 string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "StartContainer", arg0)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// StartContainer indicates an expected call of StartContainer.
func (mr *MockRuntimeServerMockRecorder) StartContainer(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "StartContainer", reflect.TypeOf((*MockRuntimeServer)(nil).StartContainer), arg0)
}

// StopContainer mocks base method.
func (m *MockRuntimeServer) StopContainer(arg0 context.Context, arg1 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "StopContainer", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// StopContainer indicates an expected call of StopContainer.
func (mr *MockRuntimeServerMockRecorder) StopContainer(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "StopContainer", reflect.TypeOf((*MockRuntimeServer)(nil).StopContainer), arg0, arg1)
}

// MockStorageTransport is a mock of StorageTransport interface.
type MockStorageTransport struct {
	ctrl     *gomock.Controller
	recorder *MockStorageTransportMockRecorder
}

// MockStorageTransportMockRecorder is the mock recorder for MockStorageTransport.
type MockStorageTransportMockRecorder struct {
	mock *MockStorageTransport
}

// NewMockStorageTransport creates a new mock instance.
func NewMockStorageTransport(ctrl *gomock.Controller) *MockStorageTransport {
	mock := &MockStorageTransport{ctrl: ctrl}
	mock.recorder = &MockStorageTransportMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockStorageTransport) EXPECT() *MockStorageTransportMockRecorder {
	return m.recorder
}

// ResolveReference mocks base method.
func (m *MockStorageTransport) ResolveReference(arg0 types.ImageReference) (types.ImageReference, *storage.Image, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ResolveReference", arg0)
	ret0, _ := ret[0].(types.ImageReference)
	ret1, _ := ret[1].(*storage.Image)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// ResolveReference indicates an expected call of ResolveReference.
func (mr *MockStorageTransportMockRecorder) ResolveReference(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ResolveReference", reflect.TypeOf((*MockStorageTransport)(nil).ResolveReference), arg0)
}
