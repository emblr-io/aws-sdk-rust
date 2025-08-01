// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The name and status of a customer agreement.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CustomerAgreement {
    /// <p>The name of the agreement.</p>
    pub agreement_name: ::std::option::Option<::std::string::String>,
    /// <p>The status of the customer agreement. This will be either <code>signed</code> or <code>unsigned</code></p>
    pub status: ::std::option::Option<::std::string::String>,
}
impl CustomerAgreement {
    /// <p>The name of the agreement.</p>
    pub fn agreement_name(&self) -> ::std::option::Option<&str> {
        self.agreement_name.as_deref()
    }
    /// <p>The status of the customer agreement. This will be either <code>signed</code> or <code>unsigned</code></p>
    pub fn status(&self) -> ::std::option::Option<&str> {
        self.status.as_deref()
    }
}
impl CustomerAgreement {
    /// Creates a new builder-style object to manufacture [`CustomerAgreement`](crate::types::CustomerAgreement).
    pub fn builder() -> crate::types::builders::CustomerAgreementBuilder {
        crate::types::builders::CustomerAgreementBuilder::default()
    }
}

/// A builder for [`CustomerAgreement`](crate::types::CustomerAgreement).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CustomerAgreementBuilder {
    pub(crate) agreement_name: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<::std::string::String>,
}
impl CustomerAgreementBuilder {
    /// <p>The name of the agreement.</p>
    pub fn agreement_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.agreement_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the agreement.</p>
    pub fn set_agreement_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.agreement_name = input;
        self
    }
    /// <p>The name of the agreement.</p>
    pub fn get_agreement_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.agreement_name
    }
    /// <p>The status of the customer agreement. This will be either <code>signed</code> or <code>unsigned</code></p>
    pub fn status(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.status = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The status of the customer agreement. This will be either <code>signed</code> or <code>unsigned</code></p>
    pub fn set_status(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the customer agreement. This will be either <code>signed</code> or <code>unsigned</code></p>
    pub fn get_status(&self) -> &::std::option::Option<::std::string::String> {
        &self.status
    }
    /// Consumes the builder and constructs a [`CustomerAgreement`](crate::types::CustomerAgreement).
    pub fn build(self) -> crate::types::CustomerAgreement {
        crate::types::CustomerAgreement {
            agreement_name: self.agreement_name,
            status: self.status,
        }
    }
}
