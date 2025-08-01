// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The summary of a worker configuration.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct WorkerConfigurationSummary {
    /// <p>The time that a worker configuration was created.</p>
    pub creation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The description of a worker configuration.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The latest revision of a worker configuration.</p>
    pub latest_revision: ::std::option::Option<crate::types::WorkerConfigurationRevisionSummary>,
    /// <p>The name of the worker configuration.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the worker configuration.</p>
    pub worker_configuration_arn: ::std::option::Option<::std::string::String>,
    /// <p>The state of the worker configuration.</p>
    pub worker_configuration_state: ::std::option::Option<crate::types::WorkerConfigurationState>,
}
impl WorkerConfigurationSummary {
    /// <p>The time that a worker configuration was created.</p>
    pub fn creation_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.creation_time.as_ref()
    }
    /// <p>The description of a worker configuration.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The latest revision of a worker configuration.</p>
    pub fn latest_revision(&self) -> ::std::option::Option<&crate::types::WorkerConfigurationRevisionSummary> {
        self.latest_revision.as_ref()
    }
    /// <p>The name of the worker configuration.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the worker configuration.</p>
    pub fn worker_configuration_arn(&self) -> ::std::option::Option<&str> {
        self.worker_configuration_arn.as_deref()
    }
    /// <p>The state of the worker configuration.</p>
    pub fn worker_configuration_state(&self) -> ::std::option::Option<&crate::types::WorkerConfigurationState> {
        self.worker_configuration_state.as_ref()
    }
}
impl WorkerConfigurationSummary {
    /// Creates a new builder-style object to manufacture [`WorkerConfigurationSummary`](crate::types::WorkerConfigurationSummary).
    pub fn builder() -> crate::types::builders::WorkerConfigurationSummaryBuilder {
        crate::types::builders::WorkerConfigurationSummaryBuilder::default()
    }
}

/// A builder for [`WorkerConfigurationSummary`](crate::types::WorkerConfigurationSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct WorkerConfigurationSummaryBuilder {
    pub(crate) creation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) latest_revision: ::std::option::Option<crate::types::WorkerConfigurationRevisionSummary>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) worker_configuration_arn: ::std::option::Option<::std::string::String>,
    pub(crate) worker_configuration_state: ::std::option::Option<crate::types::WorkerConfigurationState>,
}
impl WorkerConfigurationSummaryBuilder {
    /// <p>The time that a worker configuration was created.</p>
    pub fn creation_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.creation_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time that a worker configuration was created.</p>
    pub fn set_creation_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.creation_time = input;
        self
    }
    /// <p>The time that a worker configuration was created.</p>
    pub fn get_creation_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.creation_time
    }
    /// <p>The description of a worker configuration.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of a worker configuration.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description of a worker configuration.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The latest revision of a worker configuration.</p>
    pub fn latest_revision(mut self, input: crate::types::WorkerConfigurationRevisionSummary) -> Self {
        self.latest_revision = ::std::option::Option::Some(input);
        self
    }
    /// <p>The latest revision of a worker configuration.</p>
    pub fn set_latest_revision(mut self, input: ::std::option::Option<crate::types::WorkerConfigurationRevisionSummary>) -> Self {
        self.latest_revision = input;
        self
    }
    /// <p>The latest revision of a worker configuration.</p>
    pub fn get_latest_revision(&self) -> &::std::option::Option<crate::types::WorkerConfigurationRevisionSummary> {
        &self.latest_revision
    }
    /// <p>The name of the worker configuration.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the worker configuration.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the worker configuration.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The Amazon Resource Name (ARN) of the worker configuration.</p>
    pub fn worker_configuration_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.worker_configuration_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the worker configuration.</p>
    pub fn set_worker_configuration_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.worker_configuration_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the worker configuration.</p>
    pub fn get_worker_configuration_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.worker_configuration_arn
    }
    /// <p>The state of the worker configuration.</p>
    pub fn worker_configuration_state(mut self, input: crate::types::WorkerConfigurationState) -> Self {
        self.worker_configuration_state = ::std::option::Option::Some(input);
        self
    }
    /// <p>The state of the worker configuration.</p>
    pub fn set_worker_configuration_state(mut self, input: ::std::option::Option<crate::types::WorkerConfigurationState>) -> Self {
        self.worker_configuration_state = input;
        self
    }
    /// <p>The state of the worker configuration.</p>
    pub fn get_worker_configuration_state(&self) -> &::std::option::Option<crate::types::WorkerConfigurationState> {
        &self.worker_configuration_state
    }
    /// Consumes the builder and constructs a [`WorkerConfigurationSummary`](crate::types::WorkerConfigurationSummary).
    pub fn build(self) -> crate::types::WorkerConfigurationSummary {
        crate::types::WorkerConfigurationSummary {
            creation_time: self.creation_time,
            description: self.description,
            latest_revision: self.latest_revision,
            name: self.name,
            worker_configuration_arn: self.worker_configuration_arn,
            worker_configuration_state: self.worker_configuration_state,
        }
    }
}
