// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateEnvironmentMembershipInput {
    /// <p>The ID of the environment that contains the environment member you want to add.</p>
    pub environment_id: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the environment member you want to add.</p>
    pub user_arn: ::std::option::Option<::std::string::String>,
    /// <p>The type of environment member permissions you want to associate with this environment member. Available values include:</p>
    /// <ul>
    /// <li>
    /// <p><code>read-only</code>: Has read-only access to the environment.</p></li>
    /// <li>
    /// <p><code>read-write</code>: Has read-write access to the environment.</p></li>
    /// </ul>
    pub permissions: ::std::option::Option<crate::types::MemberPermissions>,
}
impl CreateEnvironmentMembershipInput {
    /// <p>The ID of the environment that contains the environment member you want to add.</p>
    pub fn environment_id(&self) -> ::std::option::Option<&str> {
        self.environment_id.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the environment member you want to add.</p>
    pub fn user_arn(&self) -> ::std::option::Option<&str> {
        self.user_arn.as_deref()
    }
    /// <p>The type of environment member permissions you want to associate with this environment member. Available values include:</p>
    /// <ul>
    /// <li>
    /// <p><code>read-only</code>: Has read-only access to the environment.</p></li>
    /// <li>
    /// <p><code>read-write</code>: Has read-write access to the environment.</p></li>
    /// </ul>
    pub fn permissions(&self) -> ::std::option::Option<&crate::types::MemberPermissions> {
        self.permissions.as_ref()
    }
}
impl CreateEnvironmentMembershipInput {
    /// Creates a new builder-style object to manufacture [`CreateEnvironmentMembershipInput`](crate::operation::create_environment_membership::CreateEnvironmentMembershipInput).
    pub fn builder() -> crate::operation::create_environment_membership::builders::CreateEnvironmentMembershipInputBuilder {
        crate::operation::create_environment_membership::builders::CreateEnvironmentMembershipInputBuilder::default()
    }
}

/// A builder for [`CreateEnvironmentMembershipInput`](crate::operation::create_environment_membership::CreateEnvironmentMembershipInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateEnvironmentMembershipInputBuilder {
    pub(crate) environment_id: ::std::option::Option<::std::string::String>,
    pub(crate) user_arn: ::std::option::Option<::std::string::String>,
    pub(crate) permissions: ::std::option::Option<crate::types::MemberPermissions>,
}
impl CreateEnvironmentMembershipInputBuilder {
    /// <p>The ID of the environment that contains the environment member you want to add.</p>
    /// This field is required.
    pub fn environment_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.environment_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the environment that contains the environment member you want to add.</p>
    pub fn set_environment_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.environment_id = input;
        self
    }
    /// <p>The ID of the environment that contains the environment member you want to add.</p>
    pub fn get_environment_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.environment_id
    }
    /// <p>The Amazon Resource Name (ARN) of the environment member you want to add.</p>
    /// This field is required.
    pub fn user_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.user_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the environment member you want to add.</p>
    pub fn set_user_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.user_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the environment member you want to add.</p>
    pub fn get_user_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.user_arn
    }
    /// <p>The type of environment member permissions you want to associate with this environment member. Available values include:</p>
    /// <ul>
    /// <li>
    /// <p><code>read-only</code>: Has read-only access to the environment.</p></li>
    /// <li>
    /// <p><code>read-write</code>: Has read-write access to the environment.</p></li>
    /// </ul>
    /// This field is required.
    pub fn permissions(mut self, input: crate::types::MemberPermissions) -> Self {
        self.permissions = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of environment member permissions you want to associate with this environment member. Available values include:</p>
    /// <ul>
    /// <li>
    /// <p><code>read-only</code>: Has read-only access to the environment.</p></li>
    /// <li>
    /// <p><code>read-write</code>: Has read-write access to the environment.</p></li>
    /// </ul>
    pub fn set_permissions(mut self, input: ::std::option::Option<crate::types::MemberPermissions>) -> Self {
        self.permissions = input;
        self
    }
    /// <p>The type of environment member permissions you want to associate with this environment member. Available values include:</p>
    /// <ul>
    /// <li>
    /// <p><code>read-only</code>: Has read-only access to the environment.</p></li>
    /// <li>
    /// <p><code>read-write</code>: Has read-write access to the environment.</p></li>
    /// </ul>
    pub fn get_permissions(&self) -> &::std::option::Option<crate::types::MemberPermissions> {
        &self.permissions
    }
    /// Consumes the builder and constructs a [`CreateEnvironmentMembershipInput`](crate::operation::create_environment_membership::CreateEnvironmentMembershipInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::create_environment_membership::CreateEnvironmentMembershipInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::create_environment_membership::CreateEnvironmentMembershipInput {
            environment_id: self.environment_id,
            user_arn: self.user_arn,
            permissions: self.permissions,
        })
    }
}
