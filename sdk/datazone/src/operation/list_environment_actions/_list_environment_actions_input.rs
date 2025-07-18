// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListEnvironmentActionsInput {
    /// <p>The ID of the Amazon DataZone domain in which the environment actions are listed.</p>
    pub domain_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the envrironment whose environment actions are listed.</p>
    pub environment_identifier: ::std::option::Option<::std::string::String>,
    /// <p>When the number of environment actions is greater than the default value for the <code>MaxResults</code> parameter, or if you explicitly specify a value for <code>MaxResults</code> that is less than the number of environment actions, the response includes a pagination token named <code>NextToken</code>. You can specify this <code>NextToken</code> value in a subsequent call to <code>ListEnvironmentActions</code> to list the next set of environment actions.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of environment actions to return in a single call to <code>ListEnvironmentActions</code>. When the number of environment actions to be listed is greater than the value of <code>MaxResults</code>, the response contains a <code>NextToken</code> value that you can use in a subsequent call to <code>ListEnvironmentActions</code> to list the next set of environment actions.</p>
    pub max_results: ::std::option::Option<i32>,
}
impl ListEnvironmentActionsInput {
    /// <p>The ID of the Amazon DataZone domain in which the environment actions are listed.</p>
    pub fn domain_identifier(&self) -> ::std::option::Option<&str> {
        self.domain_identifier.as_deref()
    }
    /// <p>The ID of the envrironment whose environment actions are listed.</p>
    pub fn environment_identifier(&self) -> ::std::option::Option<&str> {
        self.environment_identifier.as_deref()
    }
    /// <p>When the number of environment actions is greater than the default value for the <code>MaxResults</code> parameter, or if you explicitly specify a value for <code>MaxResults</code> that is less than the number of environment actions, the response includes a pagination token named <code>NextToken</code>. You can specify this <code>NextToken</code> value in a subsequent call to <code>ListEnvironmentActions</code> to list the next set of environment actions.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of environment actions to return in a single call to <code>ListEnvironmentActions</code>. When the number of environment actions to be listed is greater than the value of <code>MaxResults</code>, the response contains a <code>NextToken</code> value that you can use in a subsequent call to <code>ListEnvironmentActions</code> to list the next set of environment actions.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
}
impl ListEnvironmentActionsInput {
    /// Creates a new builder-style object to manufacture [`ListEnvironmentActionsInput`](crate::operation::list_environment_actions::ListEnvironmentActionsInput).
    pub fn builder() -> crate::operation::list_environment_actions::builders::ListEnvironmentActionsInputBuilder {
        crate::operation::list_environment_actions::builders::ListEnvironmentActionsInputBuilder::default()
    }
}

/// A builder for [`ListEnvironmentActionsInput`](crate::operation::list_environment_actions::ListEnvironmentActionsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListEnvironmentActionsInputBuilder {
    pub(crate) domain_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) environment_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
}
impl ListEnvironmentActionsInputBuilder {
    /// <p>The ID of the Amazon DataZone domain in which the environment actions are listed.</p>
    /// This field is required.
    pub fn domain_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the Amazon DataZone domain in which the environment actions are listed.</p>
    pub fn set_domain_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain_identifier = input;
        self
    }
    /// <p>The ID of the Amazon DataZone domain in which the environment actions are listed.</p>
    pub fn get_domain_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain_identifier
    }
    /// <p>The ID of the envrironment whose environment actions are listed.</p>
    /// This field is required.
    pub fn environment_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.environment_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the envrironment whose environment actions are listed.</p>
    pub fn set_environment_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.environment_identifier = input;
        self
    }
    /// <p>The ID of the envrironment whose environment actions are listed.</p>
    pub fn get_environment_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.environment_identifier
    }
    /// <p>When the number of environment actions is greater than the default value for the <code>MaxResults</code> parameter, or if you explicitly specify a value for <code>MaxResults</code> that is less than the number of environment actions, the response includes a pagination token named <code>NextToken</code>. You can specify this <code>NextToken</code> value in a subsequent call to <code>ListEnvironmentActions</code> to list the next set of environment actions.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>When the number of environment actions is greater than the default value for the <code>MaxResults</code> parameter, or if you explicitly specify a value for <code>MaxResults</code> that is less than the number of environment actions, the response includes a pagination token named <code>NextToken</code>. You can specify this <code>NextToken</code> value in a subsequent call to <code>ListEnvironmentActions</code> to list the next set of environment actions.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>When the number of environment actions is greater than the default value for the <code>MaxResults</code> parameter, or if you explicitly specify a value for <code>MaxResults</code> that is less than the number of environment actions, the response includes a pagination token named <code>NextToken</code>. You can specify this <code>NextToken</code> value in a subsequent call to <code>ListEnvironmentActions</code> to list the next set of environment actions.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum number of environment actions to return in a single call to <code>ListEnvironmentActions</code>. When the number of environment actions to be listed is greater than the value of <code>MaxResults</code>, the response contains a <code>NextToken</code> value that you can use in a subsequent call to <code>ListEnvironmentActions</code> to list the next set of environment actions.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of environment actions to return in a single call to <code>ListEnvironmentActions</code>. When the number of environment actions to be listed is greater than the value of <code>MaxResults</code>, the response contains a <code>NextToken</code> value that you can use in a subsequent call to <code>ListEnvironmentActions</code> to list the next set of environment actions.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of environment actions to return in a single call to <code>ListEnvironmentActions</code>. When the number of environment actions to be listed is greater than the value of <code>MaxResults</code>, the response contains a <code>NextToken</code> value that you can use in a subsequent call to <code>ListEnvironmentActions</code> to list the next set of environment actions.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Consumes the builder and constructs a [`ListEnvironmentActionsInput`](crate::operation::list_environment_actions::ListEnvironmentActionsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_environment_actions::ListEnvironmentActionsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::list_environment_actions::ListEnvironmentActionsInput {
            domain_identifier: self.domain_identifier,
            environment_identifier: self.environment_identifier,
            next_token: self.next_token,
            max_results: self.max_results,
        })
    }
}
