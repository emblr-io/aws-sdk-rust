// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The custom parameters to be used when the target is an Batch job.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BatchParameters {
    /// <p>The ARN or name of the job definition to use if the event target is an Batch job. This job definition must already exist.</p>
    pub job_definition: ::std::string::String,
    /// <p>The name to use for this execution of the job, if the target is an Batch job.</p>
    pub job_name: ::std::string::String,
    /// <p>The array properties for the submitted job, such as the size of the array. The array size can be between 2 and 10,000. If you specify array properties for a job, it becomes an array job. This parameter is used only if the target is an Batch job.</p>
    pub array_properties: ::std::option::Option<crate::types::BatchArrayProperties>,
    /// <p>The retry strategy to use for failed jobs, if the target is an Batch job. The retry strategy is the number of times to retry the failed job execution. Valid values are 1–10. When you specify a retry strategy here, it overrides the retry strategy defined in the job definition.</p>
    pub retry_strategy: ::std::option::Option<crate::types::BatchRetryStrategy>,
}
impl BatchParameters {
    /// <p>The ARN or name of the job definition to use if the event target is an Batch job. This job definition must already exist.</p>
    pub fn job_definition(&self) -> &str {
        use std::ops::Deref;
        self.job_definition.deref()
    }
    /// <p>The name to use for this execution of the job, if the target is an Batch job.</p>
    pub fn job_name(&self) -> &str {
        use std::ops::Deref;
        self.job_name.deref()
    }
    /// <p>The array properties for the submitted job, such as the size of the array. The array size can be between 2 and 10,000. If you specify array properties for a job, it becomes an array job. This parameter is used only if the target is an Batch job.</p>
    pub fn array_properties(&self) -> ::std::option::Option<&crate::types::BatchArrayProperties> {
        self.array_properties.as_ref()
    }
    /// <p>The retry strategy to use for failed jobs, if the target is an Batch job. The retry strategy is the number of times to retry the failed job execution. Valid values are 1–10. When you specify a retry strategy here, it overrides the retry strategy defined in the job definition.</p>
    pub fn retry_strategy(&self) -> ::std::option::Option<&crate::types::BatchRetryStrategy> {
        self.retry_strategy.as_ref()
    }
}
impl BatchParameters {
    /// Creates a new builder-style object to manufacture [`BatchParameters`](crate::types::BatchParameters).
    pub fn builder() -> crate::types::builders::BatchParametersBuilder {
        crate::types::builders::BatchParametersBuilder::default()
    }
}

/// A builder for [`BatchParameters`](crate::types::BatchParameters).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BatchParametersBuilder {
    pub(crate) job_definition: ::std::option::Option<::std::string::String>,
    pub(crate) job_name: ::std::option::Option<::std::string::String>,
    pub(crate) array_properties: ::std::option::Option<crate::types::BatchArrayProperties>,
    pub(crate) retry_strategy: ::std::option::Option<crate::types::BatchRetryStrategy>,
}
impl BatchParametersBuilder {
    /// <p>The ARN or name of the job definition to use if the event target is an Batch job. This job definition must already exist.</p>
    /// This field is required.
    pub fn job_definition(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.job_definition = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN or name of the job definition to use if the event target is an Batch job. This job definition must already exist.</p>
    pub fn set_job_definition(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.job_definition = input;
        self
    }
    /// <p>The ARN or name of the job definition to use if the event target is an Batch job. This job definition must already exist.</p>
    pub fn get_job_definition(&self) -> &::std::option::Option<::std::string::String> {
        &self.job_definition
    }
    /// <p>The name to use for this execution of the job, if the target is an Batch job.</p>
    /// This field is required.
    pub fn job_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.job_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name to use for this execution of the job, if the target is an Batch job.</p>
    pub fn set_job_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.job_name = input;
        self
    }
    /// <p>The name to use for this execution of the job, if the target is an Batch job.</p>
    pub fn get_job_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.job_name
    }
    /// <p>The array properties for the submitted job, such as the size of the array. The array size can be between 2 and 10,000. If you specify array properties for a job, it becomes an array job. This parameter is used only if the target is an Batch job.</p>
    pub fn array_properties(mut self, input: crate::types::BatchArrayProperties) -> Self {
        self.array_properties = ::std::option::Option::Some(input);
        self
    }
    /// <p>The array properties for the submitted job, such as the size of the array. The array size can be between 2 and 10,000. If you specify array properties for a job, it becomes an array job. This parameter is used only if the target is an Batch job.</p>
    pub fn set_array_properties(mut self, input: ::std::option::Option<crate::types::BatchArrayProperties>) -> Self {
        self.array_properties = input;
        self
    }
    /// <p>The array properties for the submitted job, such as the size of the array. The array size can be between 2 and 10,000. If you specify array properties for a job, it becomes an array job. This parameter is used only if the target is an Batch job.</p>
    pub fn get_array_properties(&self) -> &::std::option::Option<crate::types::BatchArrayProperties> {
        &self.array_properties
    }
    /// <p>The retry strategy to use for failed jobs, if the target is an Batch job. The retry strategy is the number of times to retry the failed job execution. Valid values are 1–10. When you specify a retry strategy here, it overrides the retry strategy defined in the job definition.</p>
    pub fn retry_strategy(mut self, input: crate::types::BatchRetryStrategy) -> Self {
        self.retry_strategy = ::std::option::Option::Some(input);
        self
    }
    /// <p>The retry strategy to use for failed jobs, if the target is an Batch job. The retry strategy is the number of times to retry the failed job execution. Valid values are 1–10. When you specify a retry strategy here, it overrides the retry strategy defined in the job definition.</p>
    pub fn set_retry_strategy(mut self, input: ::std::option::Option<crate::types::BatchRetryStrategy>) -> Self {
        self.retry_strategy = input;
        self
    }
    /// <p>The retry strategy to use for failed jobs, if the target is an Batch job. The retry strategy is the number of times to retry the failed job execution. Valid values are 1–10. When you specify a retry strategy here, it overrides the retry strategy defined in the job definition.</p>
    pub fn get_retry_strategy(&self) -> &::std::option::Option<crate::types::BatchRetryStrategy> {
        &self.retry_strategy
    }
    /// Consumes the builder and constructs a [`BatchParameters`](crate::types::BatchParameters).
    /// This method will fail if any of the following fields are not set:
    /// - [`job_definition`](crate::types::builders::BatchParametersBuilder::job_definition)
    /// - [`job_name`](crate::types::builders::BatchParametersBuilder::job_name)
    pub fn build(self) -> ::std::result::Result<crate::types::BatchParameters, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::BatchParameters {
            job_definition: self.job_definition.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "job_definition",
                    "job_definition was not specified but it is required when building BatchParameters",
                )
            })?,
            job_name: self.job_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "job_name",
                    "job_name was not specified but it is required when building BatchParameters",
                )
            })?,
            array_properties: self.array_properties,
            retry_strategy: self.retry_strategy,
        })
    }
}
