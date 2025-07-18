// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListTargetsInput {
    /// <p>The ID or ARN of the target group.</p>
    pub target_group_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of results to return.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>A pagination token for the next page of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The targets.</p>
    pub targets: ::std::option::Option<::std::vec::Vec<crate::types::Target>>,
}
impl ListTargetsInput {
    /// <p>The ID or ARN of the target group.</p>
    pub fn target_group_identifier(&self) -> ::std::option::Option<&str> {
        self.target_group_identifier.as_deref()
    }
    /// <p>The maximum number of results to return.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>A pagination token for the next page of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The targets.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.targets.is_none()`.
    pub fn targets(&self) -> &[crate::types::Target] {
        self.targets.as_deref().unwrap_or_default()
    }
}
impl ListTargetsInput {
    /// Creates a new builder-style object to manufacture [`ListTargetsInput`](crate::operation::list_targets::ListTargetsInput).
    pub fn builder() -> crate::operation::list_targets::builders::ListTargetsInputBuilder {
        crate::operation::list_targets::builders::ListTargetsInputBuilder::default()
    }
}

/// A builder for [`ListTargetsInput`](crate::operation::list_targets::ListTargetsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListTargetsInputBuilder {
    pub(crate) target_group_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) targets: ::std::option::Option<::std::vec::Vec<crate::types::Target>>,
}
impl ListTargetsInputBuilder {
    /// <p>The ID or ARN of the target group.</p>
    /// This field is required.
    pub fn target_group_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.target_group_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID or ARN of the target group.</p>
    pub fn set_target_group_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.target_group_identifier = input;
        self
    }
    /// <p>The ID or ARN of the target group.</p>
    pub fn get_target_group_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.target_group_identifier
    }
    /// <p>The maximum number of results to return.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results to return.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of results to return.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>A pagination token for the next page of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A pagination token for the next page of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>A pagination token for the next page of results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Appends an item to `targets`.
    ///
    /// To override the contents of this collection use [`set_targets`](Self::set_targets).
    ///
    /// <p>The targets.</p>
    pub fn targets(mut self, input: crate::types::Target) -> Self {
        let mut v = self.targets.unwrap_or_default();
        v.push(input);
        self.targets = ::std::option::Option::Some(v);
        self
    }
    /// <p>The targets.</p>
    pub fn set_targets(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Target>>) -> Self {
        self.targets = input;
        self
    }
    /// <p>The targets.</p>
    pub fn get_targets(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Target>> {
        &self.targets
    }
    /// Consumes the builder and constructs a [`ListTargetsInput`](crate::operation::list_targets::ListTargetsInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::list_targets::ListTargetsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_targets::ListTargetsInput {
            target_group_identifier: self.target_group_identifier,
            max_results: self.max_results,
            next_token: self.next_token,
            targets: self.targets,
        })
    }
}
