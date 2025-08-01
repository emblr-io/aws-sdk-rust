// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The assessment for aPersonally Identifiable Information (PII) policy.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GuardrailSensitiveInformationPolicyAssessment {
    /// <p>The PII entities in the assessment.</p>
    pub pii_entities: ::std::vec::Vec<crate::types::GuardrailPiiEntityFilter>,
    /// <p>The regex queries in the assessment.</p>
    pub regexes: ::std::vec::Vec<crate::types::GuardrailRegexFilter>,
}
impl GuardrailSensitiveInformationPolicyAssessment {
    /// <p>The PII entities in the assessment.</p>
    pub fn pii_entities(&self) -> &[crate::types::GuardrailPiiEntityFilter] {
        use std::ops::Deref;
        self.pii_entities.deref()
    }
    /// <p>The regex queries in the assessment.</p>
    pub fn regexes(&self) -> &[crate::types::GuardrailRegexFilter] {
        use std::ops::Deref;
        self.regexes.deref()
    }
}
impl GuardrailSensitiveInformationPolicyAssessment {
    /// Creates a new builder-style object to manufacture [`GuardrailSensitiveInformationPolicyAssessment`](crate::types::GuardrailSensitiveInformationPolicyAssessment).
    pub fn builder() -> crate::types::builders::GuardrailSensitiveInformationPolicyAssessmentBuilder {
        crate::types::builders::GuardrailSensitiveInformationPolicyAssessmentBuilder::default()
    }
}

/// A builder for [`GuardrailSensitiveInformationPolicyAssessment`](crate::types::GuardrailSensitiveInformationPolicyAssessment).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GuardrailSensitiveInformationPolicyAssessmentBuilder {
    pub(crate) pii_entities: ::std::option::Option<::std::vec::Vec<crate::types::GuardrailPiiEntityFilter>>,
    pub(crate) regexes: ::std::option::Option<::std::vec::Vec<crate::types::GuardrailRegexFilter>>,
}
impl GuardrailSensitiveInformationPolicyAssessmentBuilder {
    /// Appends an item to `pii_entities`.
    ///
    /// To override the contents of this collection use [`set_pii_entities`](Self::set_pii_entities).
    ///
    /// <p>The PII entities in the assessment.</p>
    pub fn pii_entities(mut self, input: crate::types::GuardrailPiiEntityFilter) -> Self {
        let mut v = self.pii_entities.unwrap_or_default();
        v.push(input);
        self.pii_entities = ::std::option::Option::Some(v);
        self
    }
    /// <p>The PII entities in the assessment.</p>
    pub fn set_pii_entities(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::GuardrailPiiEntityFilter>>) -> Self {
        self.pii_entities = input;
        self
    }
    /// <p>The PII entities in the assessment.</p>
    pub fn get_pii_entities(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::GuardrailPiiEntityFilter>> {
        &self.pii_entities
    }
    /// Appends an item to `regexes`.
    ///
    /// To override the contents of this collection use [`set_regexes`](Self::set_regexes).
    ///
    /// <p>The regex queries in the assessment.</p>
    pub fn regexes(mut self, input: crate::types::GuardrailRegexFilter) -> Self {
        let mut v = self.regexes.unwrap_or_default();
        v.push(input);
        self.regexes = ::std::option::Option::Some(v);
        self
    }
    /// <p>The regex queries in the assessment.</p>
    pub fn set_regexes(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::GuardrailRegexFilter>>) -> Self {
        self.regexes = input;
        self
    }
    /// <p>The regex queries in the assessment.</p>
    pub fn get_regexes(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::GuardrailRegexFilter>> {
        &self.regexes
    }
    /// Consumes the builder and constructs a [`GuardrailSensitiveInformationPolicyAssessment`](crate::types::GuardrailSensitiveInformationPolicyAssessment).
    /// This method will fail if any of the following fields are not set:
    /// - [`pii_entities`](crate::types::builders::GuardrailSensitiveInformationPolicyAssessmentBuilder::pii_entities)
    /// - [`regexes`](crate::types::builders::GuardrailSensitiveInformationPolicyAssessmentBuilder::regexes)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::types::GuardrailSensitiveInformationPolicyAssessment, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::GuardrailSensitiveInformationPolicyAssessment {
            pii_entities: self.pii_entities.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "pii_entities",
                    "pii_entities was not specified but it is required when building GuardrailSensitiveInformationPolicyAssessment",
                )
            })?,
            regexes: self.regexes.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "regexes",
                    "regexes was not specified but it is required when building GuardrailSensitiveInformationPolicyAssessment",
                )
            })?,
        })
    }
}
