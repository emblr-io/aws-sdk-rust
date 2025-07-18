// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes how the parts of the textQuery matched the input query by returning the sections of the response which matched to textQuery terms.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SuggestAddressHighlights {
    /// <p>Indicates the starting and ending indexes of the places in the result which were identified to match the textQuery. This result is useful for providing emphasis to results where the user query directly matched to make selecting the correct result from a list easier for an end user.</p>
    pub label: ::std::option::Option<::std::vec::Vec<crate::types::Highlight>>,
}
impl SuggestAddressHighlights {
    /// <p>Indicates the starting and ending indexes of the places in the result which were identified to match the textQuery. This result is useful for providing emphasis to results where the user query directly matched to make selecting the correct result from a list easier for an end user.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.label.is_none()`.
    pub fn label(&self) -> &[crate::types::Highlight] {
        self.label.as_deref().unwrap_or_default()
    }
}
impl SuggestAddressHighlights {
    /// Creates a new builder-style object to manufacture [`SuggestAddressHighlights`](crate::types::SuggestAddressHighlights).
    pub fn builder() -> crate::types::builders::SuggestAddressHighlightsBuilder {
        crate::types::builders::SuggestAddressHighlightsBuilder::default()
    }
}

/// A builder for [`SuggestAddressHighlights`](crate::types::SuggestAddressHighlights).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SuggestAddressHighlightsBuilder {
    pub(crate) label: ::std::option::Option<::std::vec::Vec<crate::types::Highlight>>,
}
impl SuggestAddressHighlightsBuilder {
    /// Appends an item to `label`.
    ///
    /// To override the contents of this collection use [`set_label`](Self::set_label).
    ///
    /// <p>Indicates the starting and ending indexes of the places in the result which were identified to match the textQuery. This result is useful for providing emphasis to results where the user query directly matched to make selecting the correct result from a list easier for an end user.</p>
    pub fn label(mut self, input: crate::types::Highlight) -> Self {
        let mut v = self.label.unwrap_or_default();
        v.push(input);
        self.label = ::std::option::Option::Some(v);
        self
    }
    /// <p>Indicates the starting and ending indexes of the places in the result which were identified to match the textQuery. This result is useful for providing emphasis to results where the user query directly matched to make selecting the correct result from a list easier for an end user.</p>
    pub fn set_label(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Highlight>>) -> Self {
        self.label = input;
        self
    }
    /// <p>Indicates the starting and ending indexes of the places in the result which were identified to match the textQuery. This result is useful for providing emphasis to results where the user query directly matched to make selecting the correct result from a list easier for an end user.</p>
    pub fn get_label(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Highlight>> {
        &self.label
    }
    /// Consumes the builder and constructs a [`SuggestAddressHighlights`](crate::types::SuggestAddressHighlights).
    pub fn build(self) -> crate::types::SuggestAddressHighlights {
        crate::types::SuggestAddressHighlights { label: self.label }
    }
}
