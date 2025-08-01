// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListGroupResourcesInput {
    /// <p>A token that indicates that there is more data available. You can use this token in a subsequent operation to retrieve the next set of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>Specify this parameter to limit how many canary ARNs are returned each time you use the <code>ListGroupResources</code> operation. If you omit this parameter, the default of 20 is used.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>Specifies the group to return information for. You can specify the group name, the ARN, or the group ID as the <code>GroupIdentifier</code>.</p>
    pub group_identifier: ::std::option::Option<::std::string::String>,
}
impl ListGroupResourcesInput {
    /// <p>A token that indicates that there is more data available. You can use this token in a subsequent operation to retrieve the next set of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>Specify this parameter to limit how many canary ARNs are returned each time you use the <code>ListGroupResources</code> operation. If you omit this parameter, the default of 20 is used.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>Specifies the group to return information for. You can specify the group name, the ARN, or the group ID as the <code>GroupIdentifier</code>.</p>
    pub fn group_identifier(&self) -> ::std::option::Option<&str> {
        self.group_identifier.as_deref()
    }
}
impl ListGroupResourcesInput {
    /// Creates a new builder-style object to manufacture [`ListGroupResourcesInput`](crate::operation::list_group_resources::ListGroupResourcesInput).
    pub fn builder() -> crate::operation::list_group_resources::builders::ListGroupResourcesInputBuilder {
        crate::operation::list_group_resources::builders::ListGroupResourcesInputBuilder::default()
    }
}

/// A builder for [`ListGroupResourcesInput`](crate::operation::list_group_resources::ListGroupResourcesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListGroupResourcesInputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) group_identifier: ::std::option::Option<::std::string::String>,
}
impl ListGroupResourcesInputBuilder {
    /// <p>A token that indicates that there is more data available. You can use this token in a subsequent operation to retrieve the next set of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A token that indicates that there is more data available. You can use this token in a subsequent operation to retrieve the next set of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>A token that indicates that there is more data available. You can use this token in a subsequent operation to retrieve the next set of results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>Specify this parameter to limit how many canary ARNs are returned each time you use the <code>ListGroupResources</code> operation. If you omit this parameter, the default of 20 is used.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specify this parameter to limit how many canary ARNs are returned each time you use the <code>ListGroupResources</code> operation. If you omit this parameter, the default of 20 is used.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>Specify this parameter to limit how many canary ARNs are returned each time you use the <code>ListGroupResources</code> operation. If you omit this parameter, the default of 20 is used.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>Specifies the group to return information for. You can specify the group name, the ARN, or the group ID as the <code>GroupIdentifier</code>.</p>
    /// This field is required.
    pub fn group_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.group_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the group to return information for. You can specify the group name, the ARN, or the group ID as the <code>GroupIdentifier</code>.</p>
    pub fn set_group_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.group_identifier = input;
        self
    }
    /// <p>Specifies the group to return information for. You can specify the group name, the ARN, or the group ID as the <code>GroupIdentifier</code>.</p>
    pub fn get_group_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.group_identifier
    }
    /// Consumes the builder and constructs a [`ListGroupResourcesInput`](crate::operation::list_group_resources::ListGroupResourcesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_group_resources::ListGroupResourcesInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::list_group_resources::ListGroupResourcesInput {
            next_token: self.next_token,
            max_results: self.max_results,
            group_identifier: self.group_identifier,
        })
    }
}
