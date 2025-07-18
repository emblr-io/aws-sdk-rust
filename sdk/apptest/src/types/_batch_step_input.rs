// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Defines a batch step input.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BatchStepInput {
    /// <p>The resource of the batch step input.</p>
    pub resource: ::std::option::Option<crate::types::MainframeResourceSummary>,
    /// <p>The batch job name of the batch step input.</p>
    pub batch_job_name: ::std::string::String,
    /// <p>The batch job parameters of the batch step input.</p>
    pub batch_job_parameters: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>The export data set names of the batch step input.</p>
    pub export_data_set_names: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The properties of the batch step input.</p>
    pub properties: ::std::option::Option<crate::types::MainframeActionProperties>,
}
impl BatchStepInput {
    /// <p>The resource of the batch step input.</p>
    pub fn resource(&self) -> ::std::option::Option<&crate::types::MainframeResourceSummary> {
        self.resource.as_ref()
    }
    /// <p>The batch job name of the batch step input.</p>
    pub fn batch_job_name(&self) -> &str {
        use std::ops::Deref;
        self.batch_job_name.deref()
    }
    /// <p>The batch job parameters of the batch step input.</p>
    pub fn batch_job_parameters(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.batch_job_parameters.as_ref()
    }
    /// <p>The export data set names of the batch step input.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.export_data_set_names.is_none()`.
    pub fn export_data_set_names(&self) -> &[::std::string::String] {
        self.export_data_set_names.as_deref().unwrap_or_default()
    }
    /// <p>The properties of the batch step input.</p>
    pub fn properties(&self) -> ::std::option::Option<&crate::types::MainframeActionProperties> {
        self.properties.as_ref()
    }
}
impl BatchStepInput {
    /// Creates a new builder-style object to manufacture [`BatchStepInput`](crate::types::BatchStepInput).
    pub fn builder() -> crate::types::builders::BatchStepInputBuilder {
        crate::types::builders::BatchStepInputBuilder::default()
    }
}

/// A builder for [`BatchStepInput`](crate::types::BatchStepInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BatchStepInputBuilder {
    pub(crate) resource: ::std::option::Option<crate::types::MainframeResourceSummary>,
    pub(crate) batch_job_name: ::std::option::Option<::std::string::String>,
    pub(crate) batch_job_parameters: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) export_data_set_names: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) properties: ::std::option::Option<crate::types::MainframeActionProperties>,
}
impl BatchStepInputBuilder {
    /// <p>The resource of the batch step input.</p>
    /// This field is required.
    pub fn resource(mut self, input: crate::types::MainframeResourceSummary) -> Self {
        self.resource = ::std::option::Option::Some(input);
        self
    }
    /// <p>The resource of the batch step input.</p>
    pub fn set_resource(mut self, input: ::std::option::Option<crate::types::MainframeResourceSummary>) -> Self {
        self.resource = input;
        self
    }
    /// <p>The resource of the batch step input.</p>
    pub fn get_resource(&self) -> &::std::option::Option<crate::types::MainframeResourceSummary> {
        &self.resource
    }
    /// <p>The batch job name of the batch step input.</p>
    /// This field is required.
    pub fn batch_job_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.batch_job_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The batch job name of the batch step input.</p>
    pub fn set_batch_job_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.batch_job_name = input;
        self
    }
    /// <p>The batch job name of the batch step input.</p>
    pub fn get_batch_job_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.batch_job_name
    }
    /// Adds a key-value pair to `batch_job_parameters`.
    ///
    /// To override the contents of this collection use [`set_batch_job_parameters`](Self::set_batch_job_parameters).
    ///
    /// <p>The batch job parameters of the batch step input.</p>
    pub fn batch_job_parameters(
        mut self,
        k: impl ::std::convert::Into<::std::string::String>,
        v: impl ::std::convert::Into<::std::string::String>,
    ) -> Self {
        let mut hash_map = self.batch_job_parameters.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.batch_job_parameters = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The batch job parameters of the batch step input.</p>
    pub fn set_batch_job_parameters(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    ) -> Self {
        self.batch_job_parameters = input;
        self
    }
    /// <p>The batch job parameters of the batch step input.</p>
    pub fn get_batch_job_parameters(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.batch_job_parameters
    }
    /// Appends an item to `export_data_set_names`.
    ///
    /// To override the contents of this collection use [`set_export_data_set_names`](Self::set_export_data_set_names).
    ///
    /// <p>The export data set names of the batch step input.</p>
    pub fn export_data_set_names(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.export_data_set_names.unwrap_or_default();
        v.push(input.into());
        self.export_data_set_names = ::std::option::Option::Some(v);
        self
    }
    /// <p>The export data set names of the batch step input.</p>
    pub fn set_export_data_set_names(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.export_data_set_names = input;
        self
    }
    /// <p>The export data set names of the batch step input.</p>
    pub fn get_export_data_set_names(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.export_data_set_names
    }
    /// <p>The properties of the batch step input.</p>
    pub fn properties(mut self, input: crate::types::MainframeActionProperties) -> Self {
        self.properties = ::std::option::Option::Some(input);
        self
    }
    /// <p>The properties of the batch step input.</p>
    pub fn set_properties(mut self, input: ::std::option::Option<crate::types::MainframeActionProperties>) -> Self {
        self.properties = input;
        self
    }
    /// <p>The properties of the batch step input.</p>
    pub fn get_properties(&self) -> &::std::option::Option<crate::types::MainframeActionProperties> {
        &self.properties
    }
    /// Consumes the builder and constructs a [`BatchStepInput`](crate::types::BatchStepInput).
    /// This method will fail if any of the following fields are not set:
    /// - [`batch_job_name`](crate::types::builders::BatchStepInputBuilder::batch_job_name)
    pub fn build(self) -> ::std::result::Result<crate::types::BatchStepInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::BatchStepInput {
            resource: self.resource,
            batch_job_name: self.batch_job_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "batch_job_name",
                    "batch_job_name was not specified but it is required when building BatchStepInput",
                )
            })?,
            batch_job_parameters: self.batch_job_parameters,
            export_data_set_names: self.export_data_set_names,
            properties: self.properties,
        })
    }
}
