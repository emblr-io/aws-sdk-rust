// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contextual information for the entity. The traits recognized by InferICD10CM are <code>DIAGNOSIS</code>, <code>SIGN</code>, <code>SYMPTOM</code>, and <code>NEGATION</code>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Icd10CmTrait {
    /// <p>Provides a name or contextual description about the trait.</p>
    pub name: ::std::option::Option<crate::types::Icd10CmTraitName>,
    /// <p>The level of confidence that Amazon Comprehend Medical has that the segment of text is correctly recognized as a trait.</p>
    pub score: ::std::option::Option<f32>,
}
impl Icd10CmTrait {
    /// <p>Provides a name or contextual description about the trait.</p>
    pub fn name(&self) -> ::std::option::Option<&crate::types::Icd10CmTraitName> {
        self.name.as_ref()
    }
    /// <p>The level of confidence that Amazon Comprehend Medical has that the segment of text is correctly recognized as a trait.</p>
    pub fn score(&self) -> ::std::option::Option<f32> {
        self.score
    }
}
impl Icd10CmTrait {
    /// Creates a new builder-style object to manufacture [`Icd10CmTrait`](crate::types::Icd10CmTrait).
    pub fn builder() -> crate::types::builders::Icd10CmTraitBuilder {
        crate::types::builders::Icd10CmTraitBuilder::default()
    }
}

/// A builder for [`Icd10CmTrait`](crate::types::Icd10CmTrait).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct Icd10CmTraitBuilder {
    pub(crate) name: ::std::option::Option<crate::types::Icd10CmTraitName>,
    pub(crate) score: ::std::option::Option<f32>,
}
impl Icd10CmTraitBuilder {
    /// <p>Provides a name or contextual description about the trait.</p>
    pub fn name(mut self, input: crate::types::Icd10CmTraitName) -> Self {
        self.name = ::std::option::Option::Some(input);
        self
    }
    /// <p>Provides a name or contextual description about the trait.</p>
    pub fn set_name(mut self, input: ::std::option::Option<crate::types::Icd10CmTraitName>) -> Self {
        self.name = input;
        self
    }
    /// <p>Provides a name or contextual description about the trait.</p>
    pub fn get_name(&self) -> &::std::option::Option<crate::types::Icd10CmTraitName> {
        &self.name
    }
    /// <p>The level of confidence that Amazon Comprehend Medical has that the segment of text is correctly recognized as a trait.</p>
    pub fn score(mut self, input: f32) -> Self {
        self.score = ::std::option::Option::Some(input);
        self
    }
    /// <p>The level of confidence that Amazon Comprehend Medical has that the segment of text is correctly recognized as a trait.</p>
    pub fn set_score(mut self, input: ::std::option::Option<f32>) -> Self {
        self.score = input;
        self
    }
    /// <p>The level of confidence that Amazon Comprehend Medical has that the segment of text is correctly recognized as a trait.</p>
    pub fn get_score(&self) -> &::std::option::Option<f32> {
        &self.score
    }
    /// Consumes the builder and constructs a [`Icd10CmTrait`](crate::types::Icd10CmTrait).
    pub fn build(self) -> crate::types::Icd10CmTrait {
        crate::types::Icd10CmTrait {
            name: self.name,
            score: self.score,
        }
    }
}
