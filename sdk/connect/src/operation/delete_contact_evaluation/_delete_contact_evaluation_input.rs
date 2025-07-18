// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteContactEvaluationInput {
    /// <p>The identifier of the Amazon Connect instance. You can <a href="https://docs.aws.amazon.com/connect/latest/adminguide/find-instance-arn.html">find the instance ID</a> in the Amazon Resource Name (ARN) of the instance.</p>
    pub instance_id: ::std::option::Option<::std::string::String>,
    /// <p>A unique identifier for the contact evaluation.</p>
    pub evaluation_id: ::std::option::Option<::std::string::String>,
}
impl DeleteContactEvaluationInput {
    /// <p>The identifier of the Amazon Connect instance. You can <a href="https://docs.aws.amazon.com/connect/latest/adminguide/find-instance-arn.html">find the instance ID</a> in the Amazon Resource Name (ARN) of the instance.</p>
    pub fn instance_id(&self) -> ::std::option::Option<&str> {
        self.instance_id.as_deref()
    }
    /// <p>A unique identifier for the contact evaluation.</p>
    pub fn evaluation_id(&self) -> ::std::option::Option<&str> {
        self.evaluation_id.as_deref()
    }
}
impl DeleteContactEvaluationInput {
    /// Creates a new builder-style object to manufacture [`DeleteContactEvaluationInput`](crate::operation::delete_contact_evaluation::DeleteContactEvaluationInput).
    pub fn builder() -> crate::operation::delete_contact_evaluation::builders::DeleteContactEvaluationInputBuilder {
        crate::operation::delete_contact_evaluation::builders::DeleteContactEvaluationInputBuilder::default()
    }
}

/// A builder for [`DeleteContactEvaluationInput`](crate::operation::delete_contact_evaluation::DeleteContactEvaluationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteContactEvaluationInputBuilder {
    pub(crate) instance_id: ::std::option::Option<::std::string::String>,
    pub(crate) evaluation_id: ::std::option::Option<::std::string::String>,
}
impl DeleteContactEvaluationInputBuilder {
    /// <p>The identifier of the Amazon Connect instance. You can <a href="https://docs.aws.amazon.com/connect/latest/adminguide/find-instance-arn.html">find the instance ID</a> in the Amazon Resource Name (ARN) of the instance.</p>
    /// This field is required.
    pub fn instance_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.instance_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the Amazon Connect instance. You can <a href="https://docs.aws.amazon.com/connect/latest/adminguide/find-instance-arn.html">find the instance ID</a> in the Amazon Resource Name (ARN) of the instance.</p>
    pub fn set_instance_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.instance_id = input;
        self
    }
    /// <p>The identifier of the Amazon Connect instance. You can <a href="https://docs.aws.amazon.com/connect/latest/adminguide/find-instance-arn.html">find the instance ID</a> in the Amazon Resource Name (ARN) of the instance.</p>
    pub fn get_instance_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.instance_id
    }
    /// <p>A unique identifier for the contact evaluation.</p>
    /// This field is required.
    pub fn evaluation_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.evaluation_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique identifier for the contact evaluation.</p>
    pub fn set_evaluation_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.evaluation_id = input;
        self
    }
    /// <p>A unique identifier for the contact evaluation.</p>
    pub fn get_evaluation_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.evaluation_id
    }
    /// Consumes the builder and constructs a [`DeleteContactEvaluationInput`](crate::operation::delete_contact_evaluation::DeleteContactEvaluationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::delete_contact_evaluation::DeleteContactEvaluationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::delete_contact_evaluation::DeleteContactEvaluationInput {
            instance_id: self.instance_id,
            evaluation_id: self.evaluation_id,
        })
    }
}
