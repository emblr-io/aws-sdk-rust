// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListComponentBuildVersionsInput {
    /// <p>The component version Amazon Resource Name (ARN) whose versions you want to list.</p>
    pub component_version_arn: ::std::option::Option<::std::string::String>,
    /// <p>The maximum items to return in a request.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>A token to specify where to start paginating. This is the nextToken from a previously truncated response.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
}
impl ListComponentBuildVersionsInput {
    /// <p>The component version Amazon Resource Name (ARN) whose versions you want to list.</p>
    pub fn component_version_arn(&self) -> ::std::option::Option<&str> {
        self.component_version_arn.as_deref()
    }
    /// <p>The maximum items to return in a request.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>A token to specify where to start paginating. This is the nextToken from a previously truncated response.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ListComponentBuildVersionsInput {
    /// Creates a new builder-style object to manufacture [`ListComponentBuildVersionsInput`](crate::operation::list_component_build_versions::ListComponentBuildVersionsInput).
    pub fn builder() -> crate::operation::list_component_build_versions::builders::ListComponentBuildVersionsInputBuilder {
        crate::operation::list_component_build_versions::builders::ListComponentBuildVersionsInputBuilder::default()
    }
}

/// A builder for [`ListComponentBuildVersionsInput`](crate::operation::list_component_build_versions::ListComponentBuildVersionsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListComponentBuildVersionsInputBuilder {
    pub(crate) component_version_arn: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
}
impl ListComponentBuildVersionsInputBuilder {
    /// <p>The component version Amazon Resource Name (ARN) whose versions you want to list.</p>
    /// This field is required.
    pub fn component_version_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.component_version_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The component version Amazon Resource Name (ARN) whose versions you want to list.</p>
    pub fn set_component_version_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.component_version_arn = input;
        self
    }
    /// <p>The component version Amazon Resource Name (ARN) whose versions you want to list.</p>
    pub fn get_component_version_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.component_version_arn
    }
    /// <p>The maximum items to return in a request.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum items to return in a request.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum items to return in a request.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>A token to specify where to start paginating. This is the nextToken from a previously truncated response.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A token to specify where to start paginating. This is the nextToken from a previously truncated response.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>A token to specify where to start paginating. This is the nextToken from a previously truncated response.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Consumes the builder and constructs a [`ListComponentBuildVersionsInput`](crate::operation::list_component_build_versions::ListComponentBuildVersionsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_component_build_versions::ListComponentBuildVersionsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::list_component_build_versions::ListComponentBuildVersionsInput {
            component_version_arn: self.component_version_arn,
            max_results: self.max_results,
            next_token: self.next_token,
        })
    }
}
