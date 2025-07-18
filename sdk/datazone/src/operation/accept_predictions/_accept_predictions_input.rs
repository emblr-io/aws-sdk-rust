// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AcceptPredictionsInput {
    /// <p>The identifier of the Amazon DataZone domain.</p>
    pub domain_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the asset.</p>
    pub identifier: ::std::option::Option<::std::string::String>,
    /// <p>The revision that is to be made to the asset.</p>
    pub revision: ::std::option::Option<::std::string::String>,
    /// <p>Specifies the rule (or the conditions) under which a prediction can be accepted.</p>
    pub accept_rule: ::std::option::Option<crate::types::AcceptRule>,
    /// <p>Specifies the prediction (aka, the automatically generated piece of metadata) and the target (for example, a column name) that can be accepted.</p>
    pub accept_choices: ::std::option::Option<::std::vec::Vec<crate::types::AcceptChoice>>,
    /// <p>A unique, case-sensitive identifier to ensure idempotency of the request. This field is automatically populated if not provided.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
}
impl AcceptPredictionsInput {
    /// <p>The identifier of the Amazon DataZone domain.</p>
    pub fn domain_identifier(&self) -> ::std::option::Option<&str> {
        self.domain_identifier.as_deref()
    }
    /// <p>The identifier of the asset.</p>
    pub fn identifier(&self) -> ::std::option::Option<&str> {
        self.identifier.as_deref()
    }
    /// <p>The revision that is to be made to the asset.</p>
    pub fn revision(&self) -> ::std::option::Option<&str> {
        self.revision.as_deref()
    }
    /// <p>Specifies the rule (or the conditions) under which a prediction can be accepted.</p>
    pub fn accept_rule(&self) -> ::std::option::Option<&crate::types::AcceptRule> {
        self.accept_rule.as_ref()
    }
    /// <p>Specifies the prediction (aka, the automatically generated piece of metadata) and the target (for example, a column name) that can be accepted.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.accept_choices.is_none()`.
    pub fn accept_choices(&self) -> &[crate::types::AcceptChoice] {
        self.accept_choices.as_deref().unwrap_or_default()
    }
    /// <p>A unique, case-sensitive identifier to ensure idempotency of the request. This field is automatically populated if not provided.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
}
impl AcceptPredictionsInput {
    /// Creates a new builder-style object to manufacture [`AcceptPredictionsInput`](crate::operation::accept_predictions::AcceptPredictionsInput).
    pub fn builder() -> crate::operation::accept_predictions::builders::AcceptPredictionsInputBuilder {
        crate::operation::accept_predictions::builders::AcceptPredictionsInputBuilder::default()
    }
}

/// A builder for [`AcceptPredictionsInput`](crate::operation::accept_predictions::AcceptPredictionsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AcceptPredictionsInputBuilder {
    pub(crate) domain_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) identifier: ::std::option::Option<::std::string::String>,
    pub(crate) revision: ::std::option::Option<::std::string::String>,
    pub(crate) accept_rule: ::std::option::Option<crate::types::AcceptRule>,
    pub(crate) accept_choices: ::std::option::Option<::std::vec::Vec<crate::types::AcceptChoice>>,
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
}
impl AcceptPredictionsInputBuilder {
    /// <p>The identifier of the Amazon DataZone domain.</p>
    /// This field is required.
    pub fn domain_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the Amazon DataZone domain.</p>
    pub fn set_domain_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain_identifier = input;
        self
    }
    /// <p>The identifier of the Amazon DataZone domain.</p>
    pub fn get_domain_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain_identifier
    }
    /// <p>The identifier of the asset.</p>
    /// This field is required.
    pub fn identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the asset.</p>
    pub fn set_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.identifier = input;
        self
    }
    /// <p>The identifier of the asset.</p>
    pub fn get_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.identifier
    }
    /// <p>The revision that is to be made to the asset.</p>
    pub fn revision(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.revision = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The revision that is to be made to the asset.</p>
    pub fn set_revision(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.revision = input;
        self
    }
    /// <p>The revision that is to be made to the asset.</p>
    pub fn get_revision(&self) -> &::std::option::Option<::std::string::String> {
        &self.revision
    }
    /// <p>Specifies the rule (or the conditions) under which a prediction can be accepted.</p>
    pub fn accept_rule(mut self, input: crate::types::AcceptRule) -> Self {
        self.accept_rule = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the rule (or the conditions) under which a prediction can be accepted.</p>
    pub fn set_accept_rule(mut self, input: ::std::option::Option<crate::types::AcceptRule>) -> Self {
        self.accept_rule = input;
        self
    }
    /// <p>Specifies the rule (or the conditions) under which a prediction can be accepted.</p>
    pub fn get_accept_rule(&self) -> &::std::option::Option<crate::types::AcceptRule> {
        &self.accept_rule
    }
    /// Appends an item to `accept_choices`.
    ///
    /// To override the contents of this collection use [`set_accept_choices`](Self::set_accept_choices).
    ///
    /// <p>Specifies the prediction (aka, the automatically generated piece of metadata) and the target (for example, a column name) that can be accepted.</p>
    pub fn accept_choices(mut self, input: crate::types::AcceptChoice) -> Self {
        let mut v = self.accept_choices.unwrap_or_default();
        v.push(input);
        self.accept_choices = ::std::option::Option::Some(v);
        self
    }
    /// <p>Specifies the prediction (aka, the automatically generated piece of metadata) and the target (for example, a column name) that can be accepted.</p>
    pub fn set_accept_choices(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::AcceptChoice>>) -> Self {
        self.accept_choices = input;
        self
    }
    /// <p>Specifies the prediction (aka, the automatically generated piece of metadata) and the target (for example, a column name) that can be accepted.</p>
    pub fn get_accept_choices(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AcceptChoice>> {
        &self.accept_choices
    }
    /// <p>A unique, case-sensitive identifier to ensure idempotency of the request. This field is automatically populated if not provided.</p>
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique, case-sensitive identifier to ensure idempotency of the request. This field is automatically populated if not provided.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>A unique, case-sensitive identifier to ensure idempotency of the request. This field is automatically populated if not provided.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// Consumes the builder and constructs a [`AcceptPredictionsInput`](crate::operation::accept_predictions::AcceptPredictionsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::accept_predictions::AcceptPredictionsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::accept_predictions::AcceptPredictionsInput {
            domain_identifier: self.domain_identifier,
            identifier: self.identifier,
            revision: self.revision,
            accept_rule: self.accept_rule,
            accept_choices: self.accept_choices,
            client_token: self.client_token,
        })
    }
}
