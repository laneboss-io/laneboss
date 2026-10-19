//go:build !linux

package admin

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
)

func dataOpenStageAbsent(context.Context, installation, dataJob) error {
	return failure(api.CodeUnsupported, "materialization open recovery requires Linux")
}

func (m *leaseManager) pinData(context.Context, leaseRecord, dataJob, ...[]dataCopyPayload) (*dataPins, api.StorageProjection, []byte, error) {
	return nil, api.StorageProjection{}, nil, failure(api.CodeUnsupported, "materialization descriptor projection requires Linux")
}
func rollbackDataCopies(*dataPins) error {
	return failure(api.CodeUnsupported, "copy root rollback requires Linux")
}
func checkDataPins(context.Context, leaseRecord, dataJob, *dataPins) error {
	return failure(api.CodeUnsupported, "materialization descriptor identity requires Linux")
}
func checkUnstartedDataRoots(context.Context, leaseRecord, dataJob, *dataPins) error {
	return failure(api.CodeUnsupported, "materialization preparation recovery requires Linux")
}
func (m *leaseManager) startDataGate(context.Context, leaseRecord, dataJob) (ownedGate, error) {
	return nil, failure(api.CodeUnsupported, "materialization native gate requires Linux")
}
func (m *leaseManager) dataNative(context.Context, dataReg) (DataWorkerNativeBinding, error) {
	return DataWorkerNativeBinding{}, failure(api.CodeUnsupported, "materialization native worker observation requires Linux")
}
func (m *leaseManager) readDataResult(context.Context, leaseRecord, dataJob, dataMeasure, api.ProcessObservation) (api.LaunchDataResult, error) {
	return api.LaunchDataResult{}, failure(api.CodeUnsupported, "materialization filesystem read-back requires Linux")
}
func (m *leaseManager) returnData(context.Context, leaseRecord, dataJob, []byte) error {
	return failure(api.CodeUnsupported, "materialization ownership transfer requires Linux")
}
func (s *Service) bindDataContainment(context.Context, api.StorageProjectionRequest) error {
	return failure(api.CodeUnsupported, "materialization native identity registry requires Linux")
}
func (m *leaseManager) collectDataSource(context.Context, leaseRecord, dataJob) error {
	return failure(api.CodeUnsupported, "materialization source collection requires Linux")
}
