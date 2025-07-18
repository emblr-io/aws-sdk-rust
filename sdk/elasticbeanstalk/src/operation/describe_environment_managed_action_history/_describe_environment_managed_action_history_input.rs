// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Request to list completed and failed managed actions.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeEnvironmentManagedActionHistoryInput {
    /// <p>The environment ID of the target environment.</p>
    pub environment_id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the target environment.</p>
    pub environment_name: ::std::option::Option<::std::string::String>,
    /// <p>The pagination token returned by a previous request.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of items to return for a single request.</p>
    pub max_items: ::std::option::Option<i32>,
}
impl DescribeEnvironmentManagedActionHistoryInput {
    /// <p>The environment ID of the target environment.</p>
    pub fn environment_id(&self) -> ::std::option::Option<&str> {
        self.environment_id.as_deref()
    }
    /// <p>The name of the target environment.</p>
    pub fn environment_name(&self) -> ::std::option::Option<&str> {
        self.environment_name.as_deref()
    }
    /// <p>The pagination token returned by a previous request.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of items to return for a single request.</p>
    pub fn max_items(&self) -> ::std::option::Option<i32> {
        self.max_items
    }
}
impl DescribeEnvironmentManagedActionHistoryInput {
    /// Creates a new builder-style object to manufacture [`DescribeEnvironmentManagedActionHistoryInput`](crate::operation::describe_environment_managed_action_history::DescribeEnvironmentManagedActionHistoryInput).
    pub fn builder() -> crate::operation::describe_environment_managed_action_history::builders::DescribeEnvironmentManagedActionHistoryInputBuilder {
        crate::operation::describe_environment_managed_action_history::builders::DescribeEnvironmentManagedActionHistoryInputBuilder::default()
    }
}

/// A builder for [`DescribeEnvironmentManagedActionHistoryInput`](crate::operation::describe_environment_managed_action_history::DescribeEnvironmentManagedActionHistoryInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeEnvironmentManagedActionHistoryInputBuilder {
    pub(crate) environment_id: ::std::option::Option<::std::string::String>,
    pub(crate) environment_name: ::std::option::Option<::std::string::String>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_items: ::std::option::Option<i32>,
}
impl DescribeEnvironmentManagedActionHistoryInputBuilder {
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
    /// <p>The pagination token returned by a previous request.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The pagination token returned by a previous request.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The pagination token returned by a previous request.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum number of items to return for a single request.</p>
    pub fn max_items(mut self, input: i32) -> Self {
        self.max_items = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of items to return for a single request.</p>
    pub fn set_max_items(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_items = input;
        self
    }
    /// <p>The maximum number of items to return for a single request.</p>
    pub fn get_max_items(&self) -> &::std::option::Option<i32> {
        &self.max_items
    }
    /// Consumes the builder and constructs a [`DescribeEnvironmentManagedActionHistoryInput`](crate::operation::describe_environment_managed_action_history::DescribeEnvironmentManagedActionHistoryInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_environment_managed_action_history::DescribeEnvironmentManagedActionHistoryInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::describe_environment_managed_action_history::DescribeEnvironmentManagedActionHistoryInput {
                environment_id: self.environment_id,
                environment_name: self.environment_name,
                next_token: self.next_token,
                max_items: self.max_items,
            },
        )
    }
}
