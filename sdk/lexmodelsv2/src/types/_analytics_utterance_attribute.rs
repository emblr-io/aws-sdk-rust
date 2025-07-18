// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An object that specifies the last used intent at the time of the utterance as an attribute to return.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AnalyticsUtteranceAttribute {
    /// <p>An attribute to return. The only available attribute is the intent that the bot mapped the utterance to.</p>
    pub name: crate::types::AnalyticsUtteranceAttributeName,
}
impl AnalyticsUtteranceAttribute {
    /// <p>An attribute to return. The only available attribute is the intent that the bot mapped the utterance to.</p>
    pub fn name(&self) -> &crate::types::AnalyticsUtteranceAttributeName {
        &self.name
    }
}
impl AnalyticsUtteranceAttribute {
    /// Creates a new builder-style object to manufacture [`AnalyticsUtteranceAttribute`](crate::types::AnalyticsUtteranceAttribute).
    pub fn builder() -> crate::types::builders::AnalyticsUtteranceAttributeBuilder {
        crate::types::builders::AnalyticsUtteranceAttributeBuilder::default()
    }
}

/// A builder for [`AnalyticsUtteranceAttribute`](crate::types::AnalyticsUtteranceAttribute).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AnalyticsUtteranceAttributeBuilder {
    pub(crate) name: ::std::option::Option<crate::types::AnalyticsUtteranceAttributeName>,
}
impl AnalyticsUtteranceAttributeBuilder {
    /// <p>An attribute to return. The only available attribute is the intent that the bot mapped the utterance to.</p>
    /// This field is required.
    pub fn name(mut self, input: crate::types::AnalyticsUtteranceAttributeName) -> Self {
        self.name = ::std::option::Option::Some(input);
        self
    }
    /// <p>An attribute to return. The only available attribute is the intent that the bot mapped the utterance to.</p>
    pub fn set_name(mut self, input: ::std::option::Option<crate::types::AnalyticsUtteranceAttributeName>) -> Self {
        self.name = input;
        self
    }
    /// <p>An attribute to return. The only available attribute is the intent that the bot mapped the utterance to.</p>
    pub fn get_name(&self) -> &::std::option::Option<crate::types::AnalyticsUtteranceAttributeName> {
        &self.name
    }
    /// Consumes the builder and constructs a [`AnalyticsUtteranceAttribute`](crate::types::AnalyticsUtteranceAttribute).
    /// This method will fail if any of the following fields are not set:
    /// - [`name`](crate::types::builders::AnalyticsUtteranceAttributeBuilder::name)
    pub fn build(self) -> ::std::result::Result<crate::types::AnalyticsUtteranceAttribute, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::AnalyticsUtteranceAttribute {
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building AnalyticsUtteranceAttribute",
                )
            })?,
        })
    }
}
