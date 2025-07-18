// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p></p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StartReplicationTaskAssessmentRunOutput {
    /// <p>The premigration assessment run that was started.</p>
    pub replication_task_assessment_run: ::std::option::Option<crate::types::ReplicationTaskAssessmentRun>,
    _request_id: Option<String>,
}
impl StartReplicationTaskAssessmentRunOutput {
    /// <p>The premigration assessment run that was started.</p>
    pub fn replication_task_assessment_run(&self) -> ::std::option::Option<&crate::types::ReplicationTaskAssessmentRun> {
        self.replication_task_assessment_run.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for StartReplicationTaskAssessmentRunOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl StartReplicationTaskAssessmentRunOutput {
    /// Creates a new builder-style object to manufacture [`StartReplicationTaskAssessmentRunOutput`](crate::operation::start_replication_task_assessment_run::StartReplicationTaskAssessmentRunOutput).
    pub fn builder() -> crate::operation::start_replication_task_assessment_run::builders::StartReplicationTaskAssessmentRunOutputBuilder {
        crate::operation::start_replication_task_assessment_run::builders::StartReplicationTaskAssessmentRunOutputBuilder::default()
    }
}

/// A builder for [`StartReplicationTaskAssessmentRunOutput`](crate::operation::start_replication_task_assessment_run::StartReplicationTaskAssessmentRunOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StartReplicationTaskAssessmentRunOutputBuilder {
    pub(crate) replication_task_assessment_run: ::std::option::Option<crate::types::ReplicationTaskAssessmentRun>,
    _request_id: Option<String>,
}
impl StartReplicationTaskAssessmentRunOutputBuilder {
    /// <p>The premigration assessment run that was started.</p>
    pub fn replication_task_assessment_run(mut self, input: crate::types::ReplicationTaskAssessmentRun) -> Self {
        self.replication_task_assessment_run = ::std::option::Option::Some(input);
        self
    }
    /// <p>The premigration assessment run that was started.</p>
    pub fn set_replication_task_assessment_run(mut self, input: ::std::option::Option<crate::types::ReplicationTaskAssessmentRun>) -> Self {
        self.replication_task_assessment_run = input;
        self
    }
    /// <p>The premigration assessment run that was started.</p>
    pub fn get_replication_task_assessment_run(&self) -> &::std::option::Option<crate::types::ReplicationTaskAssessmentRun> {
        &self.replication_task_assessment_run
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`StartReplicationTaskAssessmentRunOutput`](crate::operation::start_replication_task_assessment_run::StartReplicationTaskAssessmentRunOutput).
    pub fn build(self) -> crate::operation::start_replication_task_assessment_run::StartReplicationTaskAssessmentRunOutput {
        crate::operation::start_replication_task_assessment_run::StartReplicationTaskAssessmentRunOutput {
            replication_task_assessment_run: self.replication_task_assessment_run,
            _request_id: self._request_id,
        }
    }
}
