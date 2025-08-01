// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeCustomPluginOutput {
    /// <p>The time that the custom plugin was created.</p>
    pub creation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The Amazon Resource Name (ARN) of the custom plugin.</p>
    pub custom_plugin_arn: ::std::option::Option<::std::string::String>,
    /// <p>The state of the custom plugin.</p>
    pub custom_plugin_state: ::std::option::Option<crate::types::CustomPluginState>,
    /// <p>The description of the custom plugin.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The latest successfully created revision of the custom plugin. If there are no successfully created revisions, this field will be absent.</p>
    pub latest_revision: ::std::option::Option<crate::types::CustomPluginRevisionSummary>,
    /// <p>The name of the custom plugin.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>Details about the state of a custom plugin.</p>
    pub state_description: ::std::option::Option<crate::types::StateDescription>,
    _request_id: Option<String>,
}
impl DescribeCustomPluginOutput {
    /// <p>The time that the custom plugin was created.</p>
    pub fn creation_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.creation_time.as_ref()
    }
    /// <p>The Amazon Resource Name (ARN) of the custom plugin.</p>
    pub fn custom_plugin_arn(&self) -> ::std::option::Option<&str> {
        self.custom_plugin_arn.as_deref()
    }
    /// <p>The state of the custom plugin.</p>
    pub fn custom_plugin_state(&self) -> ::std::option::Option<&crate::types::CustomPluginState> {
        self.custom_plugin_state.as_ref()
    }
    /// <p>The description of the custom plugin.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The latest successfully created revision of the custom plugin. If there are no successfully created revisions, this field will be absent.</p>
    pub fn latest_revision(&self) -> ::std::option::Option<&crate::types::CustomPluginRevisionSummary> {
        self.latest_revision.as_ref()
    }
    /// <p>The name of the custom plugin.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>Details about the state of a custom plugin.</p>
    pub fn state_description(&self) -> ::std::option::Option<&crate::types::StateDescription> {
        self.state_description.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeCustomPluginOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeCustomPluginOutput {
    /// Creates a new builder-style object to manufacture [`DescribeCustomPluginOutput`](crate::operation::describe_custom_plugin::DescribeCustomPluginOutput).
    pub fn builder() -> crate::operation::describe_custom_plugin::builders::DescribeCustomPluginOutputBuilder {
        crate::operation::describe_custom_plugin::builders::DescribeCustomPluginOutputBuilder::default()
    }
}

/// A builder for [`DescribeCustomPluginOutput`](crate::operation::describe_custom_plugin::DescribeCustomPluginOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeCustomPluginOutputBuilder {
    pub(crate) creation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) custom_plugin_arn: ::std::option::Option<::std::string::String>,
    pub(crate) custom_plugin_state: ::std::option::Option<crate::types::CustomPluginState>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) latest_revision: ::std::option::Option<crate::types::CustomPluginRevisionSummary>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) state_description: ::std::option::Option<crate::types::StateDescription>,
    _request_id: Option<String>,
}
impl DescribeCustomPluginOutputBuilder {
    /// <p>The time that the custom plugin was created.</p>
    pub fn creation_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.creation_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time that the custom plugin was created.</p>
    pub fn set_creation_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.creation_time = input;
        self
    }
    /// <p>The time that the custom plugin was created.</p>
    pub fn get_creation_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.creation_time
    }
    /// <p>The Amazon Resource Name (ARN) of the custom plugin.</p>
    pub fn custom_plugin_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.custom_plugin_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the custom plugin.</p>
    pub fn set_custom_plugin_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.custom_plugin_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the custom plugin.</p>
    pub fn get_custom_plugin_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.custom_plugin_arn
    }
    /// <p>The state of the custom plugin.</p>
    pub fn custom_plugin_state(mut self, input: crate::types::CustomPluginState) -> Self {
        self.custom_plugin_state = ::std::option::Option::Some(input);
        self
    }
    /// <p>The state of the custom plugin.</p>
    pub fn set_custom_plugin_state(mut self, input: ::std::option::Option<crate::types::CustomPluginState>) -> Self {
        self.custom_plugin_state = input;
        self
    }
    /// <p>The state of the custom plugin.</p>
    pub fn get_custom_plugin_state(&self) -> &::std::option::Option<crate::types::CustomPluginState> {
        &self.custom_plugin_state
    }
    /// <p>The description of the custom plugin.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the custom plugin.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description of the custom plugin.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The latest successfully created revision of the custom plugin. If there are no successfully created revisions, this field will be absent.</p>
    pub fn latest_revision(mut self, input: crate::types::CustomPluginRevisionSummary) -> Self {
        self.latest_revision = ::std::option::Option::Some(input);
        self
    }
    /// <p>The latest successfully created revision of the custom plugin. If there are no successfully created revisions, this field will be absent.</p>
    pub fn set_latest_revision(mut self, input: ::std::option::Option<crate::types::CustomPluginRevisionSummary>) -> Self {
        self.latest_revision = input;
        self
    }
    /// <p>The latest successfully created revision of the custom plugin. If there are no successfully created revisions, this field will be absent.</p>
    pub fn get_latest_revision(&self) -> &::std::option::Option<crate::types::CustomPluginRevisionSummary> {
        &self.latest_revision
    }
    /// <p>The name of the custom plugin.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the custom plugin.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the custom plugin.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>Details about the state of a custom plugin.</p>
    pub fn state_description(mut self, input: crate::types::StateDescription) -> Self {
        self.state_description = ::std::option::Option::Some(input);
        self
    }
    /// <p>Details about the state of a custom plugin.</p>
    pub fn set_state_description(mut self, input: ::std::option::Option<crate::types::StateDescription>) -> Self {
        self.state_description = input;
        self
    }
    /// <p>Details about the state of a custom plugin.</p>
    pub fn get_state_description(&self) -> &::std::option::Option<crate::types::StateDescription> {
        &self.state_description
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeCustomPluginOutput`](crate::operation::describe_custom_plugin::DescribeCustomPluginOutput).
    pub fn build(self) -> crate::operation::describe_custom_plugin::DescribeCustomPluginOutput {
        crate::operation::describe_custom_plugin::DescribeCustomPluginOutput {
            creation_time: self.creation_time,
            custom_plugin_arn: self.custom_plugin_arn,
            custom_plugin_state: self.custom_plugin_state,
            description: self.description,
            latest_revision: self.latest_revision,
            name: self.name,
            state_description: self.state_description,
            _request_id: self._request_id,
        }
    }
}
