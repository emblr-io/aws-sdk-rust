// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An object representing the collaboration member's model inference payment responsibilities set by the collaboration creator.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ModelInferencePaymentConfig {
    /// <p>Indicates whether the collaboration creator has configured the collaboration member to pay for model inference costs (<code>TRUE</code>) or has not configured the collaboration member to pay for model inference costs (<code>FALSE</code>).</p>
    /// <p>Exactly one member can be configured to pay for model inference costs. An error is returned if the collaboration creator sets a <code>TRUE</code> value for more than one member in the collaboration.</p>
    /// <p>If the collaboration creator hasn't specified anyone as the member paying for model inference costs, then the member who can query is the default payer. An error is returned if the collaboration creator sets a <code>FALSE</code> value for the member who can query.</p>
    pub is_responsible: bool,
}
impl ModelInferencePaymentConfig {
    /// <p>Indicates whether the collaboration creator has configured the collaboration member to pay for model inference costs (<code>TRUE</code>) or has not configured the collaboration member to pay for model inference costs (<code>FALSE</code>).</p>
    /// <p>Exactly one member can be configured to pay for model inference costs. An error is returned if the collaboration creator sets a <code>TRUE</code> value for more than one member in the collaboration.</p>
    /// <p>If the collaboration creator hasn't specified anyone as the member paying for model inference costs, then the member who can query is the default payer. An error is returned if the collaboration creator sets a <code>FALSE</code> value for the member who can query.</p>
    pub fn is_responsible(&self) -> bool {
        self.is_responsible
    }
}
impl ModelInferencePaymentConfig {
    /// Creates a new builder-style object to manufacture [`ModelInferencePaymentConfig`](crate::types::ModelInferencePaymentConfig).
    pub fn builder() -> crate::types::builders::ModelInferencePaymentConfigBuilder {
        crate::types::builders::ModelInferencePaymentConfigBuilder::default()
    }
}

/// A builder for [`ModelInferencePaymentConfig`](crate::types::ModelInferencePaymentConfig).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ModelInferencePaymentConfigBuilder {
    pub(crate) is_responsible: ::std::option::Option<bool>,
}
impl ModelInferencePaymentConfigBuilder {
    /// <p>Indicates whether the collaboration creator has configured the collaboration member to pay for model inference costs (<code>TRUE</code>) or has not configured the collaboration member to pay for model inference costs (<code>FALSE</code>).</p>
    /// <p>Exactly one member can be configured to pay for model inference costs. An error is returned if the collaboration creator sets a <code>TRUE</code> value for more than one member in the collaboration.</p>
    /// <p>If the collaboration creator hasn't specified anyone as the member paying for model inference costs, then the member who can query is the default payer. An error is returned if the collaboration creator sets a <code>FALSE</code> value for the member who can query.</p>
    /// This field is required.
    pub fn is_responsible(mut self, input: bool) -> Self {
        self.is_responsible = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether the collaboration creator has configured the collaboration member to pay for model inference costs (<code>TRUE</code>) or has not configured the collaboration member to pay for model inference costs (<code>FALSE</code>).</p>
    /// <p>Exactly one member can be configured to pay for model inference costs. An error is returned if the collaboration creator sets a <code>TRUE</code> value for more than one member in the collaboration.</p>
    /// <p>If the collaboration creator hasn't specified anyone as the member paying for model inference costs, then the member who can query is the default payer. An error is returned if the collaboration creator sets a <code>FALSE</code> value for the member who can query.</p>
    pub fn set_is_responsible(mut self, input: ::std::option::Option<bool>) -> Self {
        self.is_responsible = input;
        self
    }
    /// <p>Indicates whether the collaboration creator has configured the collaboration member to pay for model inference costs (<code>TRUE</code>) or has not configured the collaboration member to pay for model inference costs (<code>FALSE</code>).</p>
    /// <p>Exactly one member can be configured to pay for model inference costs. An error is returned if the collaboration creator sets a <code>TRUE</code> value for more than one member in the collaboration.</p>
    /// <p>If the collaboration creator hasn't specified anyone as the member paying for model inference costs, then the member who can query is the default payer. An error is returned if the collaboration creator sets a <code>FALSE</code> value for the member who can query.</p>
    pub fn get_is_responsible(&self) -> &::std::option::Option<bool> {
        &self.is_responsible
    }
    /// Consumes the builder and constructs a [`ModelInferencePaymentConfig`](crate::types::ModelInferencePaymentConfig).
    /// This method will fail if any of the following fields are not set:
    /// - [`is_responsible`](crate::types::builders::ModelInferencePaymentConfigBuilder::is_responsible)
    pub fn build(self) -> ::std::result::Result<crate::types::ModelInferencePaymentConfig, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ModelInferencePaymentConfig {
            is_responsible: self.is_responsible.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "is_responsible",
                    "is_responsible was not specified but it is required when building ModelInferencePaymentConfig",
                )
            })?,
        })
    }
}
