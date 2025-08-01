// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Orphan file deletion metrics for Iceberg for the optimizer run.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct IcebergOrphanFileDeletionMetrics {
    /// <p>The number of orphan files deleted by the orphan file deletion job run.</p>
    pub number_of_orphan_files_deleted: i64,
    /// <p>The number of DPU hours consumed by the job.</p>
    pub dpu_hours: f64,
    /// <p>The number of DPUs consumed by the job, rounded up to the nearest whole number.</p>
    pub number_of_dpus: i32,
    /// <p>The duration of the job in hours.</p>
    pub job_duration_in_hour: f64,
}
impl IcebergOrphanFileDeletionMetrics {
    /// <p>The number of orphan files deleted by the orphan file deletion job run.</p>
    pub fn number_of_orphan_files_deleted(&self) -> i64 {
        self.number_of_orphan_files_deleted
    }
    /// <p>The number of DPU hours consumed by the job.</p>
    pub fn dpu_hours(&self) -> f64 {
        self.dpu_hours
    }
    /// <p>The number of DPUs consumed by the job, rounded up to the nearest whole number.</p>
    pub fn number_of_dpus(&self) -> i32 {
        self.number_of_dpus
    }
    /// <p>The duration of the job in hours.</p>
    pub fn job_duration_in_hour(&self) -> f64 {
        self.job_duration_in_hour
    }
}
impl IcebergOrphanFileDeletionMetrics {
    /// Creates a new builder-style object to manufacture [`IcebergOrphanFileDeletionMetrics`](crate::types::IcebergOrphanFileDeletionMetrics).
    pub fn builder() -> crate::types::builders::IcebergOrphanFileDeletionMetricsBuilder {
        crate::types::builders::IcebergOrphanFileDeletionMetricsBuilder::default()
    }
}

/// A builder for [`IcebergOrphanFileDeletionMetrics`](crate::types::IcebergOrphanFileDeletionMetrics).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct IcebergOrphanFileDeletionMetricsBuilder {
    pub(crate) number_of_orphan_files_deleted: ::std::option::Option<i64>,
    pub(crate) dpu_hours: ::std::option::Option<f64>,
    pub(crate) number_of_dpus: ::std::option::Option<i32>,
    pub(crate) job_duration_in_hour: ::std::option::Option<f64>,
}
impl IcebergOrphanFileDeletionMetricsBuilder {
    /// <p>The number of orphan files deleted by the orphan file deletion job run.</p>
    pub fn number_of_orphan_files_deleted(mut self, input: i64) -> Self {
        self.number_of_orphan_files_deleted = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of orphan files deleted by the orphan file deletion job run.</p>
    pub fn set_number_of_orphan_files_deleted(mut self, input: ::std::option::Option<i64>) -> Self {
        self.number_of_orphan_files_deleted = input;
        self
    }
    /// <p>The number of orphan files deleted by the orphan file deletion job run.</p>
    pub fn get_number_of_orphan_files_deleted(&self) -> &::std::option::Option<i64> {
        &self.number_of_orphan_files_deleted
    }
    /// <p>The number of DPU hours consumed by the job.</p>
    pub fn dpu_hours(mut self, input: f64) -> Self {
        self.dpu_hours = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of DPU hours consumed by the job.</p>
    pub fn set_dpu_hours(mut self, input: ::std::option::Option<f64>) -> Self {
        self.dpu_hours = input;
        self
    }
    /// <p>The number of DPU hours consumed by the job.</p>
    pub fn get_dpu_hours(&self) -> &::std::option::Option<f64> {
        &self.dpu_hours
    }
    /// <p>The number of DPUs consumed by the job, rounded up to the nearest whole number.</p>
    pub fn number_of_dpus(mut self, input: i32) -> Self {
        self.number_of_dpus = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of DPUs consumed by the job, rounded up to the nearest whole number.</p>
    pub fn set_number_of_dpus(mut self, input: ::std::option::Option<i32>) -> Self {
        self.number_of_dpus = input;
        self
    }
    /// <p>The number of DPUs consumed by the job, rounded up to the nearest whole number.</p>
    pub fn get_number_of_dpus(&self) -> &::std::option::Option<i32> {
        &self.number_of_dpus
    }
    /// <p>The duration of the job in hours.</p>
    pub fn job_duration_in_hour(mut self, input: f64) -> Self {
        self.job_duration_in_hour = ::std::option::Option::Some(input);
        self
    }
    /// <p>The duration of the job in hours.</p>
    pub fn set_job_duration_in_hour(mut self, input: ::std::option::Option<f64>) -> Self {
        self.job_duration_in_hour = input;
        self
    }
    /// <p>The duration of the job in hours.</p>
    pub fn get_job_duration_in_hour(&self) -> &::std::option::Option<f64> {
        &self.job_duration_in_hour
    }
    /// Consumes the builder and constructs a [`IcebergOrphanFileDeletionMetrics`](crate::types::IcebergOrphanFileDeletionMetrics).
    pub fn build(self) -> crate::types::IcebergOrphanFileDeletionMetrics {
        crate::types::IcebergOrphanFileDeletionMetrics {
            number_of_orphan_files_deleted: self.number_of_orphan_files_deleted.unwrap_or_default(),
            dpu_hours: self.dpu_hours.unwrap_or_default(),
            number_of_dpus: self.number_of_dpus.unwrap_or_default(),
            job_duration_in_hour: self.job_duration_in_hour.unwrap_or_default(),
        }
    }
}
