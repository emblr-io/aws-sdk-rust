// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides information about a PII entity.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PiiEntity {
    /// <p>The level of confidence that Amazon Comprehend has in the accuracy of the detection.</p>
    pub score: ::std::option::Option<f32>,
    /// <p>The entity's type.</p>
    pub r#type: ::std::option::Option<crate::types::PiiEntityType>,
    /// <p>The zero-based offset from the beginning of the source text to the first character in the entity.</p>
    pub begin_offset: ::std::option::Option<i32>,
    /// <p>The zero-based offset from the beginning of the source text to the last character in the entity.</p>
    pub end_offset: ::std::option::Option<i32>,
}
impl PiiEntity {
    /// <p>The level of confidence that Amazon Comprehend has in the accuracy of the detection.</p>
    pub fn score(&self) -> ::std::option::Option<f32> {
        self.score
    }
    /// <p>The entity's type.</p>
    pub fn r#type(&self) -> ::std::option::Option<&crate::types::PiiEntityType> {
        self.r#type.as_ref()
    }
    /// <p>The zero-based offset from the beginning of the source text to the first character in the entity.</p>
    pub fn begin_offset(&self) -> ::std::option::Option<i32> {
        self.begin_offset
    }
    /// <p>The zero-based offset from the beginning of the source text to the last character in the entity.</p>
    pub fn end_offset(&self) -> ::std::option::Option<i32> {
        self.end_offset
    }
}
impl PiiEntity {
    /// Creates a new builder-style object to manufacture [`PiiEntity`](crate::types::PiiEntity).
    pub fn builder() -> crate::types::builders::PiiEntityBuilder {
        crate::types::builders::PiiEntityBuilder::default()
    }
}

/// A builder for [`PiiEntity`](crate::types::PiiEntity).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PiiEntityBuilder {
    pub(crate) score: ::std::option::Option<f32>,
    pub(crate) r#type: ::std::option::Option<crate::types::PiiEntityType>,
    pub(crate) begin_offset: ::std::option::Option<i32>,
    pub(crate) end_offset: ::std::option::Option<i32>,
}
impl PiiEntityBuilder {
    /// <p>The level of confidence that Amazon Comprehend has in the accuracy of the detection.</p>
    pub fn score(mut self, input: f32) -> Self {
        self.score = ::std::option::Option::Some(input);
        self
    }
    /// <p>The level of confidence that Amazon Comprehend has in the accuracy of the detection.</p>
    pub fn set_score(mut self, input: ::std::option::Option<f32>) -> Self {
        self.score = input;
        self
    }
    /// <p>The level of confidence that Amazon Comprehend has in the accuracy of the detection.</p>
    pub fn get_score(&self) -> &::std::option::Option<f32> {
        &self.score
    }
    /// <p>The entity's type.</p>
    pub fn r#type(mut self, input: crate::types::PiiEntityType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The entity's type.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::PiiEntityType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The entity's type.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::PiiEntityType> {
        &self.r#type
    }
    /// <p>The zero-based offset from the beginning of the source text to the first character in the entity.</p>
    pub fn begin_offset(mut self, input: i32) -> Self {
        self.begin_offset = ::std::option::Option::Some(input);
        self
    }
    /// <p>The zero-based offset from the beginning of the source text to the first character in the entity.</p>
    pub fn set_begin_offset(mut self, input: ::std::option::Option<i32>) -> Self {
        self.begin_offset = input;
        self
    }
    /// <p>The zero-based offset from the beginning of the source text to the first character in the entity.</p>
    pub fn get_begin_offset(&self) -> &::std::option::Option<i32> {
        &self.begin_offset
    }
    /// <p>The zero-based offset from the beginning of the source text to the last character in the entity.</p>
    pub fn end_offset(mut self, input: i32) -> Self {
        self.end_offset = ::std::option::Option::Some(input);
        self
    }
    /// <p>The zero-based offset from the beginning of the source text to the last character in the entity.</p>
    pub fn set_end_offset(mut self, input: ::std::option::Option<i32>) -> Self {
        self.end_offset = input;
        self
    }
    /// <p>The zero-based offset from the beginning of the source text to the last character in the entity.</p>
    pub fn get_end_offset(&self) -> &::std::option::Option<i32> {
        &self.end_offset
    }
    /// Consumes the builder and constructs a [`PiiEntity`](crate::types::PiiEntity).
    pub fn build(self) -> crate::types::PiiEntity {
        crate::types::PiiEntity {
            score: self.score,
            r#type: self.r#type,
            begin_offset: self.begin_offset,
            end_offset: self.end_offset,
        }
    }
}
