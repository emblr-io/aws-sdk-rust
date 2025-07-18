// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Request to execute a scheduled managed action immediately.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ApplyEnvironmentManagedActionInput {
    /// <p>The name of the target environment.</p>
    pub environment_name: ::std::option::Option<::std::string::String>,
    /// <p>The environment ID of the target environment.</p>
    pub environment_id: ::std::option::Option<::std::string::String>,
    /// <p>The action ID of the scheduled managed action to execute.</p>
    pub action_id: ::std::option::Option<::std::string::String>,
}
impl ApplyEnvironmentManagedActionInput {
    /// <p>The name of the target environment.</p>
    pub fn environment_name(&self) -> ::std::option::Option<&str> {
        self.environment_name.as_deref()
    }
    /// <p>The environment ID of the target environment.</p>
    pub fn environment_id(&self) -> ::std::option::Option<&str> {
        self.environment_id.as_deref()
    }
    /// <p>The action ID of the scheduled managed action to execute.</p>
    pub fn action_id(&self) -> ::std::option::Option<&str> {
        self.action_id.as_deref()
    }
}
impl ApplyEnvironmentManagedActionInput {
    /// Creates a new builder-style object to manufacture [`ApplyEnvironmentManagedActionInput`](crate::operation::apply_environment_managed_action::ApplyEnvironmentManagedActionInput).
    pub fn builder() -> crate::operation::apply_environment_managed_action::builders::ApplyEnvironmentManagedActionInputBuilder {
        crate::operation::apply_environment_managed_action::builders::ApplyEnvironmentManagedActionInputBuilder::default()
    }
}

/// A builder for [`ApplyEnvironmentManagedActionInput`](crate::operation::apply_environment_managed_action::ApplyEnvironmentManagedActionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ApplyEnvironmentManagedActionInputBuilder {
    pub(crate) environment_name: ::std::option::Option<::std::string::String>,
    pub(crate) environment_id: ::std::option::Option<::std::string::String>,
    pub(crate) action_id: ::std::option::Option<::std::string::String>,
}
impl ApplyEnvironmentManagedActionInputBuilder {
    /// <p>The name of the target environment.</p>
    pub fn environment_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.environment_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the target environment.</p>
    pub fn set_environment_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.environment_name = input;
        self
    }
    /// <p>The name of the target environment.</p>
    pub fn get_environment_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.environment_name
    }
    /// <p>The environment ID of the target environment.</p>
    pub fn environment_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.environment_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The environment ID of the target environment.</p>
    pub fn set_environment_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.environment_id = input;
        self
    }
    /// <p>The environment ID of the target environment.</p>
    pub fn get_environment_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.environment_id
    }
    /// <p>The action ID of the scheduled managed action to execute.</p>
    /// This field is required.
    pub fn action_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.action_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The action ID of the scheduled managed action to execute.</p>
    pub fn set_action_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.action_id = input;
        self
    }
    /// <p>The action ID of the scheduled managed action to execute.</p>
    pub fn get_action_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.action_id
    }
    /// Consumes the builder and constructs a [`ApplyEnvironmentManagedActionInput`](crate::operation::apply_environment_managed_action::ApplyEnvironmentManagedActionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::apply_environment_managed_action::ApplyEnvironmentManagedActionInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::apply_environment_managed_action::ApplyEnvironmentManagedActionInput {
            environment_name: self.environment_name,
            environment_id: self.environment_id,
            action_id: self.action_id,
        })
    }
}
