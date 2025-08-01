// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents information about an offering promotion.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct OfferingPromotion {
    /// <p>The ID of the offering promotion.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>A string that describes the offering promotion.</p>
    pub description: ::std::option::Option<::std::string::String>,
}
impl OfferingPromotion {
    /// <p>The ID of the offering promotion.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>A string that describes the offering promotion.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
}
impl OfferingPromotion {
    /// Creates a new builder-style object to manufacture [`OfferingPromotion`](crate::types::OfferingPromotion).
    pub fn builder() -> crate::types::builders::OfferingPromotionBuilder {
        crate::types::builders::OfferingPromotionBuilder::default()
    }
}

/// A builder for [`OfferingPromotion`](crate::types::OfferingPromotion).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct OfferingPromotionBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
}
impl OfferingPromotionBuilder {
    /// <p>The ID of the offering promotion.</p>
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the offering promotion.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The ID of the offering promotion.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>A string that describes the offering promotion.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A string that describes the offering promotion.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>A string that describes the offering promotion.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// Consumes the builder and constructs a [`OfferingPromotion`](crate::types::OfferingPromotion).
    pub fn build(self) -> crate::types::OfferingPromotion {
        crate::types::OfferingPromotion {
            id: self.id,
            description: self.description,
        }
    }
}
