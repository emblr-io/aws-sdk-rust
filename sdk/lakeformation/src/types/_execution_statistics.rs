// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Statistics related to the processing of a query statement.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ExecutionStatistics {
    /// <p>The average time the request took to be executed.</p>
    pub average_execution_time_millis: i64,
    /// <p>The amount of data that was scanned in bytes.</p>
    pub data_scanned_bytes: i64,
    /// <p>The number of work units executed.</p>
    pub work_units_executed_count: i64,
}
impl ExecutionStatistics {
    /// <p>The average time the request took to be executed.</p>
    pub fn average_execution_time_millis(&self) -> i64 {
        self.average_execution_time_millis
    }
    /// <p>The amount of data that was scanned in bytes.</p>
    pub fn data_scanned_bytes(&self) -> i64 {
        self.data_scanned_bytes
    }
    /// <p>The number of work units executed.</p>
    pub fn work_units_executed_count(&self) -> i64 {
        self.work_units_executed_count
    }
}
impl ExecutionStatistics {
    /// Creates a new builder-style object to manufacture [`ExecutionStatistics`](crate::types::ExecutionStatistics).
    pub fn builder() -> crate::types::builders::ExecutionStatisticsBuilder {
        crate::types::builders::ExecutionStatisticsBuilder::default()
    }
}

/// A builder for [`ExecutionStatistics`](crate::types::ExecutionStatistics).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ExecutionStatisticsBuilder {
    pub(crate) average_execution_time_millis: ::std::option::Option<i64>,
    pub(crate) data_scanned_bytes: ::std::option::Option<i64>,
    pub(crate) work_units_executed_count: ::std::option::Option<i64>,
}
impl ExecutionStatisticsBuilder {
    /// <p>The average time the request took to be executed.</p>
    pub fn average_execution_time_millis(mut self, input: i64) -> Self {
        self.average_execution_time_millis = ::std::option::Option::Some(input);
        self
    }
    /// <p>The average time the request took to be executed.</p>
    pub fn set_average_execution_time_millis(mut self, input: ::std::option::Option<i64>) -> Self {
        self.average_execution_time_millis = input;
        self
    }
    /// <p>The average time the request took to be executed.</p>
    pub fn get_average_execution_time_millis(&self) -> &::std::option::Option<i64> {
        &self.average_execution_time_millis
    }
    /// <p>The amount of data that was scanned in bytes.</p>
    pub fn data_scanned_bytes(mut self, input: i64) -> Self {
        self.data_scanned_bytes = ::std::option::Option::Some(input);
        self
    }
    /// <p>The amount of data that was scanned in bytes.</p>
    pub fn set_data_scanned_bytes(mut self, input: ::std::option::Option<i64>) -> Self {
        self.data_scanned_bytes = input;
        self
    }
    /// <p>The amount of data that was scanned in bytes.</p>
    pub fn get_data_scanned_bytes(&self) -> &::std::option::Option<i64> {
        &self.data_scanned_bytes
    }
    /// <p>The number of work units executed.</p>
    pub fn work_units_executed_count(mut self, input: i64) -> Self {
        self.work_units_executed_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of work units executed.</p>
    pub fn set_work_units_executed_count(mut self, input: ::std::option::Option<i64>) -> Self {
        self.work_units_executed_count = input;
        self
    }
    /// <p>The number of work units executed.</p>
    pub fn get_work_units_executed_count(&self) -> &::std::option::Option<i64> {
        &self.work_units_executed_count
    }
    /// Consumes the builder and constructs a [`ExecutionStatistics`](crate::types::ExecutionStatistics).
    pub fn build(self) -> crate::types::ExecutionStatistics {
        crate::types::ExecutionStatistics {
            average_execution_time_millis: self.average_execution_time_millis.unwrap_or_default(),
            data_scanned_bytes: self.data_scanned_bytes.unwrap_or_default(),
            work_units_executed_count: self.work_units_executed_count.unwrap_or_default(),
        }
    }
}
