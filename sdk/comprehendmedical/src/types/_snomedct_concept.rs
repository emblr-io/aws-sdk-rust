// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The SNOMED-CT concepts that the entity could refer to, along with a score indicating the likelihood of the match.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SnomedctConcept {
    /// <p>The description of the SNOMED-CT concept.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The numeric ID for the SNOMED-CT concept.</p>
    pub code: ::std::option::Option<::std::string::String>,
    /// <p>The level of confidence Amazon Comprehend Medical has that the entity should be linked to the identified SNOMED-CT concept.</p>
    pub score: ::std::option::Option<f32>,
}
impl SnomedctConcept {
    /// <p>The description of the SNOMED-CT concept.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The numeric ID for the SNOMED-CT concept.</p>
    pub fn code(&self) -> ::std::option::Option<&str> {
        self.code.as_deref()
    }
    /// <p>The level of confidence Amazon Comprehend Medical has that the entity should be linked to the identified SNOMED-CT concept.</p>
    pub fn score(&self) -> ::std::option::Option<f32> {
        self.score
    }
}
impl SnomedctConcept {
    /// Creates a new builder-style object to manufacture [`SnomedctConcept`](crate::types::SnomedctConcept).
    pub fn builder() -> crate::types::builders::SnomedctConceptBuilder {
        crate::types::builders::SnomedctConceptBuilder::default()
    }
}

/// A builder for [`SnomedctConcept`](crate::types::SnomedctConcept).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SnomedctConceptBuilder {
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) code: ::std::option::Option<::std::string::String>,
    pub(crate) score: ::std::option::Option<f32>,
}
impl SnomedctConceptBuilder {
    /// <p>The description of the SNOMED-CT concept.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the SNOMED-CT concept.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description of the SNOMED-CT concept.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The numeric ID for the SNOMED-CT concept.</p>
    pub fn code(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.code = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The numeric ID for the SNOMED-CT concept.</p>
    pub fn set_code(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.code = input;
        self
    }
    /// <p>The numeric ID for the SNOMED-CT concept.</p>
    pub fn get_code(&self) -> &::std::option::Option<::std::string::String> {
        &self.code
    }
    /// <p>The level of confidence Amazon Comprehend Medical has that the entity should be linked to the identified SNOMED-CT concept.</p>
    pub fn score(mut self, input: f32) -> Self {
        self.score = ::std::option::Option::Some(input);
        self
    }
    /// <p>The level of confidence Amazon Comprehend Medical has that the entity should be linked to the identified SNOMED-CT concept.</p>
    pub fn set_score(mut self, input: ::std::option::Option<f32>) -> Self {
        self.score = input;
        self
    }
    /// <p>The level of confidence Amazon Comprehend Medical has that the entity should be linked to the identified SNOMED-CT concept.</p>
    pub fn get_score(&self) -> &::std::option::Option<f32> {
        &self.score
    }
    /// Consumes the builder and constructs a [`SnomedctConcept`](crate::types::SnomedctConcept).
    pub fn build(self) -> crate::types::SnomedctConcept {
        crate::types::SnomedctConcept {
            description: self.description,
            code: self.code,
            score: self.score,
        }
    }
}
