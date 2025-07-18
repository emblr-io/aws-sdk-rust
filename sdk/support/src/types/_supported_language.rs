// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A JSON-formatted object that contains the available ISO 639-1 language <code>code</code>, <code>language</code> name and langauge <code>display</code> value. The language code is what should be used in the <code>CreateCase</code> call.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SupportedLanguage {
    /// <p>2 digit ISO 639-1 code. e.g. <code>en</code></p>
    pub code: ::std::option::Option<::std::string::String>,
    /// <p>Full language description e.g. <code>ENGLISH</code></p>
    pub language: ::std::option::Option<::std::string::String>,
    /// <p>Language display value e.g. <code>ENGLISH</code></p>
    pub display: ::std::option::Option<::std::string::String>,
}
impl SupportedLanguage {
    /// <p>2 digit ISO 639-1 code. e.g. <code>en</code></p>
    pub fn code(&self) -> ::std::option::Option<&str> {
        self.code.as_deref()
    }
    /// <p>Full language description e.g. <code>ENGLISH</code></p>
    pub fn language(&self) -> ::std::option::Option<&str> {
        self.language.as_deref()
    }
    /// <p>Language display value e.g. <code>ENGLISH</code></p>
    pub fn display(&self) -> ::std::option::Option<&str> {
        self.display.as_deref()
    }
}
impl SupportedLanguage {
    /// Creates a new builder-style object to manufacture [`SupportedLanguage`](crate::types::SupportedLanguage).
    pub fn builder() -> crate::types::builders::SupportedLanguageBuilder {
        crate::types::builders::SupportedLanguageBuilder::default()
    }
}

/// A builder for [`SupportedLanguage`](crate::types::SupportedLanguage).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SupportedLanguageBuilder {
    pub(crate) code: ::std::option::Option<::std::string::String>,
    pub(crate) language: ::std::option::Option<::std::string::String>,
    pub(crate) display: ::std::option::Option<::std::string::String>,
}
impl SupportedLanguageBuilder {
    /// <p>2 digit ISO 639-1 code. e.g. <code>en</code></p>
    pub fn code(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.code = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>2 digit ISO 639-1 code. e.g. <code>en</code></p>
    pub fn set_code(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.code = input;
        self
    }
    /// <p>2 digit ISO 639-1 code. e.g. <code>en</code></p>
    pub fn get_code(&self) -> &::std::option::Option<::std::string::String> {
        &self.code
    }
    /// <p>Full language description e.g. <code>ENGLISH</code></p>
    pub fn language(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.language = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Full language description e.g. <code>ENGLISH</code></p>
    pub fn set_language(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.language = input;
        self
    }
    /// <p>Full language description e.g. <code>ENGLISH</code></p>
    pub fn get_language(&self) -> &::std::option::Option<::std::string::String> {
        &self.language
    }
    /// <p>Language display value e.g. <code>ENGLISH</code></p>
    pub fn display(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.display = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Language display value e.g. <code>ENGLISH</code></p>
    pub fn set_display(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.display = input;
        self
    }
    /// <p>Language display value e.g. <code>ENGLISH</code></p>
    pub fn get_display(&self) -> &::std::option::Option<::std::string::String> {
        &self.display
    }
    /// Consumes the builder and constructs a [`SupportedLanguage`](crate::types::SupportedLanguage).
    pub fn build(self) -> crate::types::SupportedLanguage {
        crate::types::SupportedLanguage {
            code: self.code,
            language: self.language,
            display: self.display,
        }
    }
}
