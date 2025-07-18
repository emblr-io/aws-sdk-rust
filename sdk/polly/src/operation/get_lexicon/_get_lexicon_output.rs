// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetLexiconOutput {
    /// <p>Lexicon object that provides name and the string content of the lexicon.</p>
    pub lexicon: ::std::option::Option<crate::types::Lexicon>,
    /// <p>Metadata of the lexicon, including phonetic alphabetic used, language code, lexicon ARN, number of lexemes defined in the lexicon, and size of lexicon in bytes.</p>
    pub lexicon_attributes: ::std::option::Option<crate::types::LexiconAttributes>,
    _request_id: Option<String>,
}
impl GetLexiconOutput {
    /// <p>Lexicon object that provides name and the string content of the lexicon.</p>
    pub fn lexicon(&self) -> ::std::option::Option<&crate::types::Lexicon> {
        self.lexicon.as_ref()
    }
    /// <p>Metadata of the lexicon, including phonetic alphabetic used, language code, lexicon ARN, number of lexemes defined in the lexicon, and size of lexicon in bytes.</p>
    pub fn lexicon_attributes(&self) -> ::std::option::Option<&crate::types::LexiconAttributes> {
        self.lexicon_attributes.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetLexiconOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetLexiconOutput {
    /// Creates a new builder-style object to manufacture [`GetLexiconOutput`](crate::operation::get_lexicon::GetLexiconOutput).
    pub fn builder() -> crate::operation::get_lexicon::builders::GetLexiconOutputBuilder {
        crate::operation::get_lexicon::builders::GetLexiconOutputBuilder::default()
    }
}

/// A builder for [`GetLexiconOutput`](crate::operation::get_lexicon::GetLexiconOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetLexiconOutputBuilder {
    pub(crate) lexicon: ::std::option::Option<crate::types::Lexicon>,
    pub(crate) lexicon_attributes: ::std::option::Option<crate::types::LexiconAttributes>,
    _request_id: Option<String>,
}
impl GetLexiconOutputBuilder {
    /// <p>Lexicon object that provides name and the string content of the lexicon.</p>
    pub fn lexicon(mut self, input: crate::types::Lexicon) -> Self {
        self.lexicon = ::std::option::Option::Some(input);
        self
    }
    /// <p>Lexicon object that provides name and the string content of the lexicon.</p>
    pub fn set_lexicon(mut self, input: ::std::option::Option<crate::types::Lexicon>) -> Self {
        self.lexicon = input;
        self
    }
    /// <p>Lexicon object that provides name and the string content of the lexicon.</p>
    pub fn get_lexicon(&self) -> &::std::option::Option<crate::types::Lexicon> {
        &self.lexicon
    }
    /// <p>Metadata of the lexicon, including phonetic alphabetic used, language code, lexicon ARN, number of lexemes defined in the lexicon, and size of lexicon in bytes.</p>
    pub fn lexicon_attributes(mut self, input: crate::types::LexiconAttributes) -> Self {
        self.lexicon_attributes = ::std::option::Option::Some(input);
        self
    }
    /// <p>Metadata of the lexicon, including phonetic alphabetic used, language code, lexicon ARN, number of lexemes defined in the lexicon, and size of lexicon in bytes.</p>
    pub fn set_lexicon_attributes(mut self, input: ::std::option::Option<crate::types::LexiconAttributes>) -> Self {
        self.lexicon_attributes = input;
        self
    }
    /// <p>Metadata of the lexicon, including phonetic alphabetic used, language code, lexicon ARN, number of lexemes defined in the lexicon, and size of lexicon in bytes.</p>
    pub fn get_lexicon_attributes(&self) -> &::std::option::Option<crate::types::LexiconAttributes> {
        &self.lexicon_attributes
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetLexiconOutput`](crate::operation::get_lexicon::GetLexiconOutput).
    pub fn build(self) -> crate::operation::get_lexicon::GetLexiconOutput {
        crate::operation::get_lexicon::GetLexiconOutput {
            lexicon: self.lexicon,
            lexicon_attributes: self.lexicon_attributes,
            _request_id: self._request_id,
        }
    }
}
