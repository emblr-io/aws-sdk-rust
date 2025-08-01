// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains the output of GetPipelineDefinition.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetPipelineDefinitionOutput {
    /// <p>The objects defined in the pipeline.</p>
    pub pipeline_objects: ::std::option::Option<::std::vec::Vec<crate::types::PipelineObject>>,
    /// <p>The parameter objects used in the pipeline definition.</p>
    pub parameter_objects: ::std::option::Option<::std::vec::Vec<crate::types::ParameterObject>>,
    /// <p>The parameter values used in the pipeline definition.</p>
    pub parameter_values: ::std::option::Option<::std::vec::Vec<crate::types::ParameterValue>>,
    _request_id: Option<String>,
}
impl GetPipelineDefinitionOutput {
    /// <p>The objects defined in the pipeline.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.pipeline_objects.is_none()`.
    pub fn pipeline_objects(&self) -> &[crate::types::PipelineObject] {
        self.pipeline_objects.as_deref().unwrap_or_default()
    }
    /// <p>The parameter objects used in the pipeline definition.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.parameter_objects.is_none()`.
    pub fn parameter_objects(&self) -> &[crate::types::ParameterObject] {
        self.parameter_objects.as_deref().unwrap_or_default()
    }
    /// <p>The parameter values used in the pipeline definition.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.parameter_values.is_none()`.
    pub fn parameter_values(&self) -> &[crate::types::ParameterValue] {
        self.parameter_values.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for GetPipelineDefinitionOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetPipelineDefinitionOutput {
    /// Creates a new builder-style object to manufacture [`GetPipelineDefinitionOutput`](crate::operation::get_pipeline_definition::GetPipelineDefinitionOutput).
    pub fn builder() -> crate::operation::get_pipeline_definition::builders::GetPipelineDefinitionOutputBuilder {
        crate::operation::get_pipeline_definition::builders::GetPipelineDefinitionOutputBuilder::default()
    }
}

/// A builder for [`GetPipelineDefinitionOutput`](crate::operation::get_pipeline_definition::GetPipelineDefinitionOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetPipelineDefinitionOutputBuilder {
    pub(crate) pipeline_objects: ::std::option::Option<::std::vec::Vec<crate::types::PipelineObject>>,
    pub(crate) parameter_objects: ::std::option::Option<::std::vec::Vec<crate::types::ParameterObject>>,
    pub(crate) parameter_values: ::std::option::Option<::std::vec::Vec<crate::types::ParameterValue>>,
    _request_id: Option<String>,
}
impl GetPipelineDefinitionOutputBuilder {
    /// Appends an item to `pipeline_objects`.
    ///
    /// To override the contents of this collection use [`set_pipeline_objects`](Self::set_pipeline_objects).
    ///
    /// <p>The objects defined in the pipeline.</p>
    pub fn pipeline_objects(mut self, input: crate::types::PipelineObject) -> Self {
        let mut v = self.pipeline_objects.unwrap_or_default();
        v.push(input);
        self.pipeline_objects = ::std::option::Option::Some(v);
        self
    }
    /// <p>The objects defined in the pipeline.</p>
    pub fn set_pipeline_objects(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::PipelineObject>>) -> Self {
        self.pipeline_objects = input;
        self
    }
    /// <p>The objects defined in the pipeline.</p>
    pub fn get_pipeline_objects(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::PipelineObject>> {
        &self.pipeline_objects
    }
    /// Appends an item to `parameter_objects`.
    ///
    /// To override the contents of this collection use [`set_parameter_objects`](Self::set_parameter_objects).
    ///
    /// <p>The parameter objects used in the pipeline definition.</p>
    pub fn parameter_objects(mut self, input: crate::types::ParameterObject) -> Self {
        let mut v = self.parameter_objects.unwrap_or_default();
        v.push(input);
        self.parameter_objects = ::std::option::Option::Some(v);
        self
    }
    /// <p>The parameter objects used in the pipeline definition.</p>
    pub fn set_parameter_objects(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ParameterObject>>) -> Self {
        self.parameter_objects = input;
        self
    }
    /// <p>The parameter objects used in the pipeline definition.</p>
    pub fn get_parameter_objects(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ParameterObject>> {
        &self.parameter_objects
    }
    /// Appends an item to `parameter_values`.
    ///
    /// To override the contents of this collection use [`set_parameter_values`](Self::set_parameter_values).
    ///
    /// <p>The parameter values used in the pipeline definition.</p>
    pub fn parameter_values(mut self, input: crate::types::ParameterValue) -> Self {
        let mut v = self.parameter_values.unwrap_or_default();
        v.push(input);
        self.parameter_values = ::std::option::Option::Some(v);
        self
    }
    /// <p>The parameter values used in the pipeline definition.</p>
    pub fn set_parameter_values(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ParameterValue>>) -> Self {
        self.parameter_values = input;
        self
    }
    /// <p>The parameter values used in the pipeline definition.</p>
    pub fn get_parameter_values(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ParameterValue>> {
        &self.parameter_values
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetPipelineDefinitionOutput`](crate::operation::get_pipeline_definition::GetPipelineDefinitionOutput).
    pub fn build(self) -> crate::operation::get_pipeline_definition::GetPipelineDefinitionOutput {
        crate::operation::get_pipeline_definition::GetPipelineDefinitionOutput {
            pipeline_objects: self.pipeline_objects,
            parameter_objects: self.parameter_objects,
            parameter_values: self.parameter_values,
            _request_id: self._request_id,
        }
    }
}
