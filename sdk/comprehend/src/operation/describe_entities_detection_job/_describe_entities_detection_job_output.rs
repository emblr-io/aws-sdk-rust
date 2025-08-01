// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeEntitiesDetectionJobOutput {
    /// <p>An object that contains the properties associated with an entities detection job.</p>
    pub entities_detection_job_properties: ::std::option::Option<crate::types::EntitiesDetectionJobProperties>,
    _request_id: Option<String>,
}
impl DescribeEntitiesDetectionJobOutput {
    /// <p>An object that contains the properties associated with an entities detection job.</p>
    pub fn entities_detection_job_properties(&self) -> ::std::option::Option<&crate::types::EntitiesDetectionJobProperties> {
        self.entities_detection_job_properties.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeEntitiesDetectionJobOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeEntitiesDetectionJobOutput {
    /// Creates a new builder-style object to manufacture [`DescribeEntitiesDetectionJobOutput`](crate::operation::describe_entities_detection_job::DescribeEntitiesDetectionJobOutput).
    pub fn builder() -> crate::operation::describe_entities_detection_job::builders::DescribeEntitiesDetectionJobOutputBuilder {
        crate::operation::describe_entities_detection_job::builders::DescribeEntitiesDetectionJobOutputBuilder::default()
    }
}

/// A builder for [`DescribeEntitiesDetectionJobOutput`](crate::operation::describe_entities_detection_job::DescribeEntitiesDetectionJobOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeEntitiesDetectionJobOutputBuilder {
    pub(crate) entities_detection_job_properties: ::std::option::Option<crate::types::EntitiesDetectionJobProperties>,
    _request_id: Option<String>,
}
impl DescribeEntitiesDetectionJobOutputBuilder {
    /// <p>An object that contains the properties associated with an entities detection job.</p>
    pub fn entities_detection_job_properties(mut self, input: crate::types::EntitiesDetectionJobProperties) -> Self {
        self.entities_detection_job_properties = ::std::option::Option::Some(input);
        self
    }
    /// <p>An object that contains the properties associated with an entities detection job.</p>
    pub fn set_entities_detection_job_properties(mut self, input: ::std::option::Option<crate::types::EntitiesDetectionJobProperties>) -> Self {
        self.entities_detection_job_properties = input;
        self
    }
    /// <p>An object that contains the properties associated with an entities detection job.</p>
    pub fn get_entities_detection_job_properties(&self) -> &::std::option::Option<crate::types::EntitiesDetectionJobProperties> {
        &self.entities_detection_job_properties
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeEntitiesDetectionJobOutput`](crate::operation::describe_entities_detection_job::DescribeEntitiesDetectionJobOutput).
    pub fn build(self) -> crate::operation::describe_entities_detection_job::DescribeEntitiesDetectionJobOutput {
        crate::operation::describe_entities_detection_job::DescribeEntitiesDetectionJobOutput {
            entities_detection_job_properties: self.entities_detection_job_properties,
            _request_id: self._request_id,
        }
    }
}
