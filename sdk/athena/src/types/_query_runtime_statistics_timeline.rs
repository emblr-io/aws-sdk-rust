// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Timeline statistics such as query queue time, planning time, execution time, service processing time, and total execution time.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct QueryRuntimeStatisticsTimeline {
    /// <p>The number of milliseconds that the query was in your query queue waiting for resources. Note that if transient errors occur, Athena might automatically add the query back to the queue.</p>
    pub query_queue_time_in_millis: ::std::option::Option<i64>,
    /// <p>The number of milliseconds that Athena spends on preprocessing before it submits the query to the engine.</p>
    pub service_pre_processing_time_in_millis: ::std::option::Option<i64>,
    /// <p>The number of milliseconds that Athena took to plan the query processing flow. This includes the time spent retrieving table partitions from the data source. Note that because the query engine performs the query planning, query planning time is a subset of engine processing time.</p>
    pub query_planning_time_in_millis: ::std::option::Option<i64>,
    /// <p>The number of milliseconds that the query took to execute.</p>
    pub engine_execution_time_in_millis: ::std::option::Option<i64>,
    /// <p>The number of milliseconds that Athena took to finalize and publish the query results after the query engine finished running the query.</p>
    pub service_processing_time_in_millis: ::std::option::Option<i64>,
    /// <p>The number of milliseconds that Athena took to run the query.</p>
    pub total_execution_time_in_millis: ::std::option::Option<i64>,
}
impl QueryRuntimeStatisticsTimeline {
    /// <p>The number of milliseconds that the query was in your query queue waiting for resources. Note that if transient errors occur, Athena might automatically add the query back to the queue.</p>
    pub fn query_queue_time_in_millis(&self) -> ::std::option::Option<i64> {
        self.query_queue_time_in_millis
    }
    /// <p>The number of milliseconds that Athena spends on preprocessing before it submits the query to the engine.</p>
    pub fn service_pre_processing_time_in_millis(&self) -> ::std::option::Option<i64> {
        self.service_pre_processing_time_in_millis
    }
    /// <p>The number of milliseconds that Athena took to plan the query processing flow. This includes the time spent retrieving table partitions from the data source. Note that because the query engine performs the query planning, query planning time is a subset of engine processing time.</p>
    pub fn query_planning_time_in_millis(&self) -> ::std::option::Option<i64> {
        self.query_planning_time_in_millis
    }
    /// <p>The number of milliseconds that the query took to execute.</p>
    pub fn engine_execution_time_in_millis(&self) -> ::std::option::Option<i64> {
        self.engine_execution_time_in_millis
    }
    /// <p>The number of milliseconds that Athena took to finalize and publish the query results after the query engine finished running the query.</p>
    pub fn service_processing_time_in_millis(&self) -> ::std::option::Option<i64> {
        self.service_processing_time_in_millis
    }
    /// <p>The number of milliseconds that Athena took to run the query.</p>
    pub fn total_execution_time_in_millis(&self) -> ::std::option::Option<i64> {
        self.total_execution_time_in_millis
    }
}
impl QueryRuntimeStatisticsTimeline {
    /// Creates a new builder-style object to manufacture [`QueryRuntimeStatisticsTimeline`](crate::types::QueryRuntimeStatisticsTimeline).
    pub fn builder() -> crate::types::builders::QueryRuntimeStatisticsTimelineBuilder {
        crate::types::builders::QueryRuntimeStatisticsTimelineBuilder::default()
    }
}

/// A builder for [`QueryRuntimeStatisticsTimeline`](crate::types::QueryRuntimeStatisticsTimeline).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct QueryRuntimeStatisticsTimelineBuilder {
    pub(crate) query_queue_time_in_millis: ::std::option::Option<i64>,
    pub(crate) service_pre_processing_time_in_millis: ::std::option::Option<i64>,
    pub(crate) query_planning_time_in_millis: ::std::option::Option<i64>,
    pub(crate) engine_execution_time_in_millis: ::std::option::Option<i64>,
    pub(crate) service_processing_time_in_millis: ::std::option::Option<i64>,
    pub(crate) total_execution_time_in_millis: ::std::option::Option<i64>,
}
impl QueryRuntimeStatisticsTimelineBuilder {
    /// <p>The number of milliseconds that the query was in your query queue waiting for resources. Note that if transient errors occur, Athena might automatically add the query back to the queue.</p>
    pub fn query_queue_time_in_millis(mut self, input: i64) -> Self {
        self.query_queue_time_in_millis = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of milliseconds that the query was in your query queue waiting for resources. Note that if transient errors occur, Athena might automatically add the query back to the queue.</p>
    pub fn set_query_queue_time_in_millis(mut self, input: ::std::option::Option<i64>) -> Self {
        self.query_queue_time_in_millis = input;
        self
    }
    /// <p>The number of milliseconds that the query was in your query queue waiting for resources. Note that if transient errors occur, Athena might automatically add the query back to the queue.</p>
    pub fn get_query_queue_time_in_millis(&self) -> &::std::option::Option<i64> {
        &self.query_queue_time_in_millis
    }
    /// <p>The number of milliseconds that Athena spends on preprocessing before it submits the query to the engine.</p>
    pub fn service_pre_processing_time_in_millis(mut self, input: i64) -> Self {
        self.service_pre_processing_time_in_millis = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of milliseconds that Athena spends on preprocessing before it submits the query to the engine.</p>
    pub fn set_service_pre_processing_time_in_millis(mut self, input: ::std::option::Option<i64>) -> Self {
        self.service_pre_processing_time_in_millis = input;
        self
    }
    /// <p>The number of milliseconds that Athena spends on preprocessing before it submits the query to the engine.</p>
    pub fn get_service_pre_processing_time_in_millis(&self) -> &::std::option::Option<i64> {
        &self.service_pre_processing_time_in_millis
    }
    /// <p>The number of milliseconds that Athena took to plan the query processing flow. This includes the time spent retrieving table partitions from the data source. Note that because the query engine performs the query planning, query planning time is a subset of engine processing time.</p>
    pub fn query_planning_time_in_millis(mut self, input: i64) -> Self {
        self.query_planning_time_in_millis = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of milliseconds that Athena took to plan the query processing flow. This includes the time spent retrieving table partitions from the data source. Note that because the query engine performs the query planning, query planning time is a subset of engine processing time.</p>
    pub fn set_query_planning_time_in_millis(mut self, input: ::std::option::Option<i64>) -> Self {
        self.query_planning_time_in_millis = input;
        self
    }
    /// <p>The number of milliseconds that Athena took to plan the query processing flow. This includes the time spent retrieving table partitions from the data source. Note that because the query engine performs the query planning, query planning time is a subset of engine processing time.</p>
    pub fn get_query_planning_time_in_millis(&self) -> &::std::option::Option<i64> {
        &self.query_planning_time_in_millis
    }
    /// <p>The number of milliseconds that the query took to execute.</p>
    pub fn engine_execution_time_in_millis(mut self, input: i64) -> Self {
        self.engine_execution_time_in_millis = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of milliseconds that the query took to execute.</p>
    pub fn set_engine_execution_time_in_millis(mut self, input: ::std::option::Option<i64>) -> Self {
        self.engine_execution_time_in_millis = input;
        self
    }
    /// <p>The number of milliseconds that the query took to execute.</p>
    pub fn get_engine_execution_time_in_millis(&self) -> &::std::option::Option<i64> {
        &self.engine_execution_time_in_millis
    }
    /// <p>The number of milliseconds that Athena took to finalize and publish the query results after the query engine finished running the query.</p>
    pub fn service_processing_time_in_millis(mut self, input: i64) -> Self {
        self.service_processing_time_in_millis = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of milliseconds that Athena took to finalize and publish the query results after the query engine finished running the query.</p>
    pub fn set_service_processing_time_in_millis(mut self, input: ::std::option::Option<i64>) -> Self {
        self.service_processing_time_in_millis = input;
        self
    }
    /// <p>The number of milliseconds that Athena took to finalize and publish the query results after the query engine finished running the query.</p>
    pub fn get_service_processing_time_in_millis(&self) -> &::std::option::Option<i64> {
        &self.service_processing_time_in_millis
    }
    /// <p>The number of milliseconds that Athena took to run the query.</p>
    pub fn total_execution_time_in_millis(mut self, input: i64) -> Self {
        self.total_execution_time_in_millis = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of milliseconds that Athena took to run the query.</p>
    pub fn set_total_execution_time_in_millis(mut self, input: ::std::option::Option<i64>) -> Self {
        self.total_execution_time_in_millis = input;
        self
    }
    /// <p>The number of milliseconds that Athena took to run the query.</p>
    pub fn get_total_execution_time_in_millis(&self) -> &::std::option::Option<i64> {
        &self.total_execution_time_in_millis
    }
    /// Consumes the builder and constructs a [`QueryRuntimeStatisticsTimeline`](crate::types::QueryRuntimeStatisticsTimeline).
    pub fn build(self) -> crate::types::QueryRuntimeStatisticsTimeline {
        crate::types::QueryRuntimeStatisticsTimeline {
            query_queue_time_in_millis: self.query_queue_time_in_millis,
            service_pre_processing_time_in_millis: self.service_pre_processing_time_in_millis,
            query_planning_time_in_millis: self.query_planning_time_in_millis,
            engine_execution_time_in_millis: self.engine_execution_time_in_millis,
            service_processing_time_in_millis: self.service_processing_time_in_millis,
            total_execution_time_in_millis: self.total_execution_time_in_millis,
        }
    }
}
