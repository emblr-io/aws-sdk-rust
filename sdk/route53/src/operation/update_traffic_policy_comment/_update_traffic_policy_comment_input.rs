// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A complex type that contains information about the traffic policy that you want to update the comment for.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateTrafficPolicyCommentInput {
    /// <p>The value of <code>Id</code> for the traffic policy that you want to update the comment for.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>The value of <code>Version</code> for the traffic policy that you want to update the comment for.</p>
    pub version: ::std::option::Option<i32>,
    /// <p>The new comment for the specified traffic policy and version.</p>
    pub comment: ::std::option::Option<::std::string::String>,
}
impl UpdateTrafficPolicyCommentInput {
    /// <p>The value of <code>Id</code> for the traffic policy that you want to update the comment for.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>The value of <code>Version</code> for the traffic policy that you want to update the comment for.</p>
    pub fn version(&self) -> ::std::option::Option<i32> {
        self.version
    }
    /// <p>The new comment for the specified traffic policy and version.</p>
    pub fn comment(&self) -> ::std::option::Option<&str> {
        self.comment.as_deref()
    }
}
impl UpdateTrafficPolicyCommentInput {
    /// Creates a new builder-style object to manufacture [`UpdateTrafficPolicyCommentInput`](crate::operation::update_traffic_policy_comment::UpdateTrafficPolicyCommentInput).
    pub fn builder() -> crate::operation::update_traffic_policy_comment::builders::UpdateTrafficPolicyCommentInputBuilder {
        crate::operation::update_traffic_policy_comment::builders::UpdateTrafficPolicyCommentInputBuilder::default()
    }
}

/// A builder for [`UpdateTrafficPolicyCommentInput`](crate::operation::update_traffic_policy_comment::UpdateTrafficPolicyCommentInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateTrafficPolicyCommentInputBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) version: ::std::option::Option<i32>,
    pub(crate) comment: ::std::option::Option<::std::string::String>,
}
impl UpdateTrafficPolicyCommentInputBuilder {
    /// <p>The value of <code>Id</code> for the traffic policy that you want to update the comment for.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The value of <code>Id</code> for the traffic policy that you want to update the comment for.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The value of <code>Id</code> for the traffic policy that you want to update the comment for.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The value of <code>Version</code> for the traffic policy that you want to update the comment for.</p>
    /// This field is required.
    pub fn version(mut self, input: i32) -> Self {
        self.version = ::std::option::Option::Some(input);
        self
    }
    /// <p>The value of <code>Version</code> for the traffic policy that you want to update the comment for.</p>
    pub fn set_version(mut self, input: ::std::option::Option<i32>) -> Self {
        self.version = input;
        self
    }
    /// <p>The value of <code>Version</code> for the traffic policy that you want to update the comment for.</p>
    pub fn get_version(&self) -> &::std::option::Option<i32> {
        &self.version
    }
    /// <p>The new comment for the specified traffic policy and version.</p>
    /// This field is required.
    pub fn comment(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.comment = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The new comment for the specified traffic policy and version.</p>
    pub fn set_comment(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.comment = input;
        self
    }
    /// <p>The new comment for the specified traffic policy and version.</p>
    pub fn get_comment(&self) -> &::std::option::Option<::std::string::String> {
        &self.comment
    }
    /// Consumes the builder and constructs a [`UpdateTrafficPolicyCommentInput`](crate::operation::update_traffic_policy_comment::UpdateTrafficPolicyCommentInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::update_traffic_policy_comment::UpdateTrafficPolicyCommentInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::update_traffic_policy_comment::UpdateTrafficPolicyCommentInput {
            id: self.id,
            version: self.version,
            comment: self.comment,
        })
    }
}
