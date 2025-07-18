// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DetachPolicyInput {
    /// <p>The Amazon Resource Name (ARN) that is associated with the <code>Directory</code> where both objects reside. For more information, see <code>arns</code>.</p>
    pub directory_arn: ::std::option::Option<::std::string::String>,
    /// <p>Reference that identifies the policy object.</p>
    pub policy_reference: ::std::option::Option<crate::types::ObjectReference>,
    /// <p>Reference that identifies the object whose policy object will be detached.</p>
    pub object_reference: ::std::option::Option<crate::types::ObjectReference>,
}
impl DetachPolicyInput {
    /// <p>The Amazon Resource Name (ARN) that is associated with the <code>Directory</code> where both objects reside. For more information, see <code>arns</code>.</p>
    pub fn directory_arn(&self) -> ::std::option::Option<&str> {
        self.directory_arn.as_deref()
    }
    /// <p>Reference that identifies the policy object.</p>
    pub fn policy_reference(&self) -> ::std::option::Option<&crate::types::ObjectReference> {
        self.policy_reference.as_ref()
    }
    /// <p>Reference that identifies the object whose policy object will be detached.</p>
    pub fn object_reference(&self) -> ::std::option::Option<&crate::types::ObjectReference> {
        self.object_reference.as_ref()
    }
}
impl DetachPolicyInput {
    /// Creates a new builder-style object to manufacture [`DetachPolicyInput`](crate::operation::detach_policy::DetachPolicyInput).
    pub fn builder() -> crate::operation::detach_policy::builders::DetachPolicyInputBuilder {
        crate::operation::detach_policy::builders::DetachPolicyInputBuilder::default()
    }
}

/// A builder for [`DetachPolicyInput`](crate::operation::detach_policy::DetachPolicyInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DetachPolicyInputBuilder {
    pub(crate) directory_arn: ::std::option::Option<::std::string::String>,
    pub(crate) policy_reference: ::std::option::Option<crate::types::ObjectReference>,
    pub(crate) object_reference: ::std::option::Option<crate::types::ObjectReference>,
}
impl DetachPolicyInputBuilder {
    /// <p>The Amazon Resource Name (ARN) that is associated with the <code>Directory</code> where both objects reside. For more information, see <code>arns</code>.</p>
    /// This field is required.
    pub fn directory_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.directory_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) that is associated with the <code>Directory</code> where both objects reside. For more information, see <code>arns</code>.</p>
    pub fn set_directory_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.directory_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) that is associated with the <code>Directory</code> where both objects reside. For more information, see <code>arns</code>.</p>
    pub fn get_directory_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.directory_arn
    }
    /// <p>Reference that identifies the policy object.</p>
    /// This field is required.
    pub fn policy_reference(mut self, input: crate::types::ObjectReference) -> Self {
        self.policy_reference = ::std::option::Option::Some(input);
        self
    }
    /// <p>Reference that identifies the policy object.</p>
    pub fn set_policy_reference(mut self, input: ::std::option::Option<crate::types::ObjectReference>) -> Self {
        self.policy_reference = input;
        self
    }
    /// <p>Reference that identifies the policy object.</p>
    pub fn get_policy_reference(&self) -> &::std::option::Option<crate::types::ObjectReference> {
        &self.policy_reference
    }
    /// <p>Reference that identifies the object whose policy object will be detached.</p>
    /// This field is required.
    pub fn object_reference(mut self, input: crate::types::ObjectReference) -> Self {
        self.object_reference = ::std::option::Option::Some(input);
        self
    }
    /// <p>Reference that identifies the object whose policy object will be detached.</p>
    pub fn set_object_reference(mut self, input: ::std::option::Option<crate::types::ObjectReference>) -> Self {
        self.object_reference = input;
        self
    }
    /// <p>Reference that identifies the object whose policy object will be detached.</p>
    pub fn get_object_reference(&self) -> &::std::option::Option<crate::types::ObjectReference> {
        &self.object_reference
    }
    /// Consumes the builder and constructs a [`DetachPolicyInput`](crate::operation::detach_policy::DetachPolicyInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::detach_policy::DetachPolicyInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::detach_policy::DetachPolicyInput {
            directory_arn: self.directory_arn,
            policy_reference: self.policy_reference,
            object_reference: self.object_reference,
        })
    }
}
