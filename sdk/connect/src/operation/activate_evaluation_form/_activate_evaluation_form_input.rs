// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ActivateEvaluationFormInput {
    /// <p>The identifier of the Amazon Connect instance. You can <a href="https://docs.aws.amazon.com/connect/latest/adminguide/find-instance-arn.html">find the instance ID</a> in the Amazon Resource Name (ARN) of the instance.</p>
    pub instance_id: ::std::option::Option<::std::string::String>,
    /// <p>The unique identifier for the evaluation form.</p>
    pub evaluation_form_id: ::std::option::Option<::std::string::String>,
    /// <p>The version of the evaluation form to activate. If the version property is not provided, the latest version of the evaluation form is activated.</p>
    pub evaluation_form_version: ::std::option::Option<i32>,
}
impl ActivateEvaluationFormInput {
    /// <p>The identifier of the Amazon Connect instance. You can <a href="https://docs.aws.amazon.com/connect/latest/adminguide/find-instance-arn.html">find the instance ID</a> in the Amazon Resource Name (ARN) of the instance.</p>
    pub fn instance_id(&self) -> ::std::option::Option<&str> {
        self.instance_id.as_deref()
    }
    /// <p>The unique identifier for the evaluation form.</p>
    pub fn evaluation_form_id(&self) -> ::std::option::Option<&str> {
        self.evaluation_form_id.as_deref()
    }
    /// <p>The version of the evaluation form to activate. If the version property is not provided, the latest version of the evaluation form is activated.</p>
    pub fn evaluation_form_version(&self) -> ::std::option::Option<i32> {
        self.evaluation_form_version
    }
}
impl ActivateEvaluationFormInput {
    /// Creates a new builder-style object to manufacture [`ActivateEvaluationFormInput`](crate::operation::activate_evaluation_form::ActivateEvaluationFormInput).
    pub fn builder() -> crate::operation::activate_evaluation_form::builders::ActivateEvaluationFormInputBuilder {
        crate::operation::activate_evaluation_form::builders::ActivateEvaluationFormInputBuilder::default()
    }
}

/// A builder for [`ActivateEvaluationFormInput`](crate::operation::activate_evaluation_form::ActivateEvaluationFormInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ActivateEvaluationFormInputBuilder {
    pub(crate) instance_id: ::std::option::Option<::std::string::String>,
    pub(crate) evaluation_form_id: ::std::option::Option<::std::string::String>,
    pub(crate) evaluation_form_version: ::std::option::Option<i32>,
}
impl ActivateEvaluationFormInputBuilder {
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
    /// <p>The unique identifier for the evaluation form.</p>
    /// This field is required.
    pub fn evaluation_form_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.evaluation_form_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for the evaluation form.</p>
    pub fn set_evaluation_form_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.evaluation_form_id = input;
        self
    }
    /// <p>The unique identifier for the evaluation form.</p>
    pub fn get_evaluation_form_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.evaluation_form_id
    }
    /// <p>The version of the evaluation form to activate. If the version property is not provided, the latest version of the evaluation form is activated.</p>
    /// This field is required.
    pub fn evaluation_form_version(mut self, input: i32) -> Self {
        self.evaluation_form_version = ::std::option::Option::Some(input);
        self
    }
    /// <p>The version of the evaluation form to activate. If the version property is not provided, the latest version of the evaluation form is activated.</p>
    pub fn set_evaluation_form_version(mut self, input: ::std::option::Option<i32>) -> Self {
        self.evaluation_form_version = input;
        self
    }
    /// <p>The version of the evaluation form to activate. If the version property is not provided, the latest version of the evaluation form is activated.</p>
    pub fn get_evaluation_form_version(&self) -> &::std::option::Option<i32> {
        &self.evaluation_form_version
    }
    /// Consumes the builder and constructs a [`ActivateEvaluationFormInput`](crate::operation::activate_evaluation_form::ActivateEvaluationFormInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::activate_evaluation_form::ActivateEvaluationFormInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::activate_evaluation_form::ActivateEvaluationFormInput {
            instance_id: self.instance_id,
            evaluation_form_id: self.evaluation_form_id,
            evaluation_form_version: self.evaluation_form_version,
        })
    }
}
