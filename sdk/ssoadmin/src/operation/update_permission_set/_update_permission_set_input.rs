// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdatePermissionSetInput {
    /// <p>The ARN of the IAM Identity Center instance under which the operation will be executed. For more information about ARNs, see <a href="/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs) and Amazon Web Services Service Namespaces</a> in the <i>Amazon Web Services General Reference</i>.</p>
    pub instance_arn: ::std::option::Option<::std::string::String>,
    /// <p>The ARN of the permission set.</p>
    pub permission_set_arn: ::std::option::Option<::std::string::String>,
    /// <p>The description of the <code>PermissionSet</code>.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The length of time that the application user sessions are valid for in the ISO-8601 standard.</p>
    pub session_duration: ::std::option::Option<::std::string::String>,
    /// <p>Used to redirect users within the application during the federation authentication process.</p>
    pub relay_state: ::std::option::Option<::std::string::String>,
}
impl UpdatePermissionSetInput {
    /// <p>The ARN of the IAM Identity Center instance under which the operation will be executed. For more information about ARNs, see <a href="/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs) and Amazon Web Services Service Namespaces</a> in the <i>Amazon Web Services General Reference</i>.</p>
    pub fn instance_arn(&self) -> ::std::option::Option<&str> {
        self.instance_arn.as_deref()
    }
    /// <p>The ARN of the permission set.</p>
    pub fn permission_set_arn(&self) -> ::std::option::Option<&str> {
        self.permission_set_arn.as_deref()
    }
    /// <p>The description of the <code>PermissionSet</code>.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The length of time that the application user sessions are valid for in the ISO-8601 standard.</p>
    pub fn session_duration(&self) -> ::std::option::Option<&str> {
        self.session_duration.as_deref()
    }
    /// <p>Used to redirect users within the application during the federation authentication process.</p>
    pub fn relay_state(&self) -> ::std::option::Option<&str> {
        self.relay_state.as_deref()
    }
}
impl UpdatePermissionSetInput {
    /// Creates a new builder-style object to manufacture [`UpdatePermissionSetInput`](crate::operation::update_permission_set::UpdatePermissionSetInput).
    pub fn builder() -> crate::operation::update_permission_set::builders::UpdatePermissionSetInputBuilder {
        crate::operation::update_permission_set::builders::UpdatePermissionSetInputBuilder::default()
    }
}

/// A builder for [`UpdatePermissionSetInput`](crate::operation::update_permission_set::UpdatePermissionSetInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdatePermissionSetInputBuilder {
    pub(crate) instance_arn: ::std::option::Option<::std::string::String>,
    pub(crate) permission_set_arn: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) session_duration: ::std::option::Option<::std::string::String>,
    pub(crate) relay_state: ::std::option::Option<::std::string::String>,
}
impl UpdatePermissionSetInputBuilder {
    /// <p>The ARN of the IAM Identity Center instance under which the operation will be executed. For more information about ARNs, see <a href="/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs) and Amazon Web Services Service Namespaces</a> in the <i>Amazon Web Services General Reference</i>.</p>
    /// This field is required.
    pub fn instance_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.instance_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the IAM Identity Center instance under which the operation will be executed. For more information about ARNs, see <a href="/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs) and Amazon Web Services Service Namespaces</a> in the <i>Amazon Web Services General Reference</i>.</p>
    pub fn set_instance_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.instance_arn = input;
        self
    }
    /// <p>The ARN of the IAM Identity Center instance under which the operation will be executed. For more information about ARNs, see <a href="/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs) and Amazon Web Services Service Namespaces</a> in the <i>Amazon Web Services General Reference</i>.</p>
    pub fn get_instance_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.instance_arn
    }
    /// <p>The ARN of the permission set.</p>
    /// This field is required.
    pub fn permission_set_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.permission_set_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the permission set.</p>
    pub fn set_permission_set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.permission_set_arn = input;
        self
    }
    /// <p>The ARN of the permission set.</p>
    pub fn get_permission_set_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.permission_set_arn
    }
    /// <p>The description of the <code>PermissionSet</code>.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the <code>PermissionSet</code>.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description of the <code>PermissionSet</code>.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The length of time that the application user sessions are valid for in the ISO-8601 standard.</p>
    pub fn session_duration(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.session_duration = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The length of time that the application user sessions are valid for in the ISO-8601 standard.</p>
    pub fn set_session_duration(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.session_duration = input;
        self
    }
    /// <p>The length of time that the application user sessions are valid for in the ISO-8601 standard.</p>
    pub fn get_session_duration(&self) -> &::std::option::Option<::std::string::String> {
        &self.session_duration
    }
    /// <p>Used to redirect users within the application during the federation authentication process.</p>
    pub fn relay_state(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.relay_state = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Used to redirect users within the application during the federation authentication process.</p>
    pub fn set_relay_state(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.relay_state = input;
        self
    }
    /// <p>Used to redirect users within the application during the federation authentication process.</p>
    pub fn get_relay_state(&self) -> &::std::option::Option<::std::string::String> {
        &self.relay_state
    }
    /// Consumes the builder and constructs a [`UpdatePermissionSetInput`](crate::operation::update_permission_set::UpdatePermissionSetInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_permission_set::UpdatePermissionSetInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::update_permission_set::UpdatePermissionSetInput {
            instance_arn: self.instance_arn,
            permission_set_arn: self.permission_set_arn,
            description: self.description,
            session_duration: self.session_duration,
            relay_state: self.relay_state,
        })
    }
}
