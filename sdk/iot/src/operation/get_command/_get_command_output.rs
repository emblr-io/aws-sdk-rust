// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetCommandOutput {
    /// <p>The unique identifier of the command.</p>
    pub command_id: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Number (ARN) of the command. For example, <code>arn:aws:iot:<region>
    /// :
    /// <accountid>
    /// :command/
    /// <commandid></commandid>
    /// </accountid>
    /// </region></code></p>
    pub command_arn: ::std::option::Option<::std::string::String>,
    /// <p>The namespace of the command.</p>
    pub namespace: ::std::option::Option<crate::types::CommandNamespace>,
    /// <p>The user-friendly name in the console for the command.</p>
    pub display_name: ::std::option::Option<::std::string::String>,
    /// <p>A short text description of the command.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>A list of parameters for the command created.</p>
    pub mandatory_parameters: ::std::option::Option<::std::vec::Vec<crate::types::CommandParameter>>,
    /// <p>The payload object that you provided for the command.</p>
    pub payload: ::std::option::Option<crate::types::CommandPayload>,
    /// <p>The IAM role that you provided when creating the command with <code>AWS-IoT-FleetWise</code> as the namespace.</p>
    pub role_arn: ::std::option::Option<::std::string::String>,
    /// <p>The timestamp, when the command was created.</p>
    pub created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The timestamp, when the command was last updated.</p>
    pub last_updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>Indicates whether the command has been deprecated.</p>
    pub deprecated: ::std::option::Option<bool>,
    /// <p>Indicates whether the command is being deleted.</p>
    pub pending_deletion: ::std::option::Option<bool>,
    _request_id: Option<String>,
}
impl GetCommandOutput {
    /// <p>The unique identifier of the command.</p>
    pub fn command_id(&self) -> ::std::option::Option<&str> {
        self.command_id.as_deref()
    }
    /// <p>The Amazon Resource Number (ARN) of the command. For example, <code>arn:aws:iot:<region>
    /// :
    /// <accountid>
    /// :command/
    /// <commandid></commandid>
    /// </accountid>
    /// </region></code></p>
    pub fn command_arn(&self) -> ::std::option::Option<&str> {
        self.command_arn.as_deref()
    }
    /// <p>The namespace of the command.</p>
    pub fn namespace(&self) -> ::std::option::Option<&crate::types::CommandNamespace> {
        self.namespace.as_ref()
    }
    /// <p>The user-friendly name in the console for the command.</p>
    pub fn display_name(&self) -> ::std::option::Option<&str> {
        self.display_name.as_deref()
    }
    /// <p>A short text description of the command.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>A list of parameters for the command created.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.mandatory_parameters.is_none()`.
    pub fn mandatory_parameters(&self) -> &[crate::types::CommandParameter] {
        self.mandatory_parameters.as_deref().unwrap_or_default()
    }
    /// <p>The payload object that you provided for the command.</p>
    pub fn payload(&self) -> ::std::option::Option<&crate::types::CommandPayload> {
        self.payload.as_ref()
    }
    /// <p>The IAM role that you provided when creating the command with <code>AWS-IoT-FleetWise</code> as the namespace.</p>
    pub fn role_arn(&self) -> ::std::option::Option<&str> {
        self.role_arn.as_deref()
    }
    /// <p>The timestamp, when the command was created.</p>
    pub fn created_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.created_at.as_ref()
    }
    /// <p>The timestamp, when the command was last updated.</p>
    pub fn last_updated_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_updated_at.as_ref()
    }
    /// <p>Indicates whether the command has been deprecated.</p>
    pub fn deprecated(&self) -> ::std::option::Option<bool> {
        self.deprecated
    }
    /// <p>Indicates whether the command is being deleted.</p>
    pub fn pending_deletion(&self) -> ::std::option::Option<bool> {
        self.pending_deletion
    }
}
impl ::aws_types::request_id::RequestId for GetCommandOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetCommandOutput {
    /// Creates a new builder-style object to manufacture [`GetCommandOutput`](crate::operation::get_command::GetCommandOutput).
    pub fn builder() -> crate::operation::get_command::builders::GetCommandOutputBuilder {
        crate::operation::get_command::builders::GetCommandOutputBuilder::default()
    }
}

/// A builder for [`GetCommandOutput`](crate::operation::get_command::GetCommandOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetCommandOutputBuilder {
    pub(crate) command_id: ::std::option::Option<::std::string::String>,
    pub(crate) command_arn: ::std::option::Option<::std::string::String>,
    pub(crate) namespace: ::std::option::Option<crate::types::CommandNamespace>,
    pub(crate) display_name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) mandatory_parameters: ::std::option::Option<::std::vec::Vec<crate::types::CommandParameter>>,
    pub(crate) payload: ::std::option::Option<crate::types::CommandPayload>,
    pub(crate) role_arn: ::std::option::Option<::std::string::String>,
    pub(crate) created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) last_updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) deprecated: ::std::option::Option<bool>,
    pub(crate) pending_deletion: ::std::option::Option<bool>,
    _request_id: Option<String>,
}
impl GetCommandOutputBuilder {
    /// <p>The unique identifier of the command.</p>
    pub fn command_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.command_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the command.</p>
    pub fn set_command_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.command_id = input;
        self
    }
    /// <p>The unique identifier of the command.</p>
    pub fn get_command_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.command_id
    }
    /// <p>The Amazon Resource Number (ARN) of the command. For example, <code>arn:aws:iot:<region>
    /// :
    /// <accountid>
    /// :command/
    /// <commandid></commandid>
    /// </accountid>
    /// </region></code></p>
    pub fn command_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.command_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Number (ARN) of the command. For example, <code>arn:aws:iot:<region>
    /// :
    /// <accountid>
    /// :command/
    /// <commandid></commandid>
    /// </accountid>
    /// </region></code></p>
    pub fn set_command_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.command_arn = input;
        self
    }
    /// <p>The Amazon Resource Number (ARN) of the command. For example, <code>arn:aws:iot:<region>
    /// :
    /// <accountid>
    /// :command/
    /// <commandid></commandid>
    /// </accountid>
    /// </region></code></p>
    pub fn get_command_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.command_arn
    }
    /// <p>The namespace of the command.</p>
    pub fn namespace(mut self, input: crate::types::CommandNamespace) -> Self {
        self.namespace = ::std::option::Option::Some(input);
        self
    }
    /// <p>The namespace of the command.</p>
    pub fn set_namespace(mut self, input: ::std::option::Option<crate::types::CommandNamespace>) -> Self {
        self.namespace = input;
        self
    }
    /// <p>The namespace of the command.</p>
    pub fn get_namespace(&self) -> &::std::option::Option<crate::types::CommandNamespace> {
        &self.namespace
    }
    /// <p>The user-friendly name in the console for the command.</p>
    pub fn display_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.display_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The user-friendly name in the console for the command.</p>
    pub fn set_display_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.display_name = input;
        self
    }
    /// <p>The user-friendly name in the console for the command.</p>
    pub fn get_display_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.display_name
    }
    /// <p>A short text description of the command.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A short text description of the command.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>A short text description of the command.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// Appends an item to `mandatory_parameters`.
    ///
    /// To override the contents of this collection use [`set_mandatory_parameters`](Self::set_mandatory_parameters).
    ///
    /// <p>A list of parameters for the command created.</p>
    pub fn mandatory_parameters(mut self, input: crate::types::CommandParameter) -> Self {
        let mut v = self.mandatory_parameters.unwrap_or_default();
        v.push(input);
        self.mandatory_parameters = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of parameters for the command created.</p>
    pub fn set_mandatory_parameters(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::CommandParameter>>) -> Self {
        self.mandatory_parameters = input;
        self
    }
    /// <p>A list of parameters for the command created.</p>
    pub fn get_mandatory_parameters(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::CommandParameter>> {
        &self.mandatory_parameters
    }
    /// <p>The payload object that you provided for the command.</p>
    pub fn payload(mut self, input: crate::types::CommandPayload) -> Self {
        self.payload = ::std::option::Option::Some(input);
        self
    }
    /// <p>The payload object that you provided for the command.</p>
    pub fn set_payload(mut self, input: ::std::option::Option<crate::types::CommandPayload>) -> Self {
        self.payload = input;
        self
    }
    /// <p>The payload object that you provided for the command.</p>
    pub fn get_payload(&self) -> &::std::option::Option<crate::types::CommandPayload> {
        &self.payload
    }
    /// <p>The IAM role that you provided when creating the command with <code>AWS-IoT-FleetWise</code> as the namespace.</p>
    pub fn role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The IAM role that you provided when creating the command with <code>AWS-IoT-FleetWise</code> as the namespace.</p>
    pub fn set_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.role_arn = input;
        self
    }
    /// <p>The IAM role that you provided when creating the command with <code>AWS-IoT-FleetWise</code> as the namespace.</p>
    pub fn get_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.role_arn
    }
    /// <p>The timestamp, when the command was created.</p>
    pub fn created_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp, when the command was created.</p>
    pub fn set_created_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_at = input;
        self
    }
    /// <p>The timestamp, when the command was created.</p>
    pub fn get_created_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_at
    }
    /// <p>The timestamp, when the command was last updated.</p>
    pub fn last_updated_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_updated_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp, when the command was last updated.</p>
    pub fn set_last_updated_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_updated_at = input;
        self
    }
    /// <p>The timestamp, when the command was last updated.</p>
    pub fn get_last_updated_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_updated_at
    }
    /// <p>Indicates whether the command has been deprecated.</p>
    pub fn deprecated(mut self, input: bool) -> Self {
        self.deprecated = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether the command has been deprecated.</p>
    pub fn set_deprecated(mut self, input: ::std::option::Option<bool>) -> Self {
        self.deprecated = input;
        self
    }
    /// <p>Indicates whether the command has been deprecated.</p>
    pub fn get_deprecated(&self) -> &::std::option::Option<bool> {
        &self.deprecated
    }
    /// <p>Indicates whether the command is being deleted.</p>
    pub fn pending_deletion(mut self, input: bool) -> Self {
        self.pending_deletion = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether the command is being deleted.</p>
    pub fn set_pending_deletion(mut self, input: ::std::option::Option<bool>) -> Self {
        self.pending_deletion = input;
        self
    }
    /// <p>Indicates whether the command is being deleted.</p>
    pub fn get_pending_deletion(&self) -> &::std::option::Option<bool> {
        &self.pending_deletion
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetCommandOutput`](crate::operation::get_command::GetCommandOutput).
    pub fn build(self) -> crate::operation::get_command::GetCommandOutput {
        crate::operation::get_command::GetCommandOutput {
            command_id: self.command_id,
            command_arn: self.command_arn,
            namespace: self.namespace,
            display_name: self.display_name,
            description: self.description,
            mandatory_parameters: self.mandatory_parameters,
            payload: self.payload,
            role_arn: self.role_arn,
            created_at: self.created_at,
            last_updated_at: self.last_updated_at,
            deprecated: self.deprecated,
            pending_deletion: self.pending_deletion,
            _request_id: self._request_id,
        }
    }
}
