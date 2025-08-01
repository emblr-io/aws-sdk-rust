// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Attributes that are related to the media stream.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct MediaStreamAttributesRequest {
    /// <p>The settings that you want to use to define the media stream.</p>
    pub fmtp: ::std::option::Option<crate::types::FmtpRequest>,
    /// <p>The audio language, in a format that is recognized by the receiver.</p>
    pub lang: ::std::option::Option<::std::string::String>,
}
impl MediaStreamAttributesRequest {
    /// <p>The settings that you want to use to define the media stream.</p>
    pub fn fmtp(&self) -> ::std::option::Option<&crate::types::FmtpRequest> {
        self.fmtp.as_ref()
    }
    /// <p>The audio language, in a format that is recognized by the receiver.</p>
    pub fn lang(&self) -> ::std::option::Option<&str> {
        self.lang.as_deref()
    }
}
impl MediaStreamAttributesRequest {
    /// Creates a new builder-style object to manufacture [`MediaStreamAttributesRequest`](crate::types::MediaStreamAttributesRequest).
    pub fn builder() -> crate::types::builders::MediaStreamAttributesRequestBuilder {
        crate::types::builders::MediaStreamAttributesRequestBuilder::default()
    }
}

/// A builder for [`MediaStreamAttributesRequest`](crate::types::MediaStreamAttributesRequest).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct MediaStreamAttributesRequestBuilder {
    pub(crate) fmtp: ::std::option::Option<crate::types::FmtpRequest>,
    pub(crate) lang: ::std::option::Option<::std::string::String>,
}
impl MediaStreamAttributesRequestBuilder {
    /// <p>The settings that you want to use to define the media stream.</p>
    pub fn fmtp(mut self, input: crate::types::FmtpRequest) -> Self {
        self.fmtp = ::std::option::Option::Some(input);
        self
    }
    /// <p>The settings that you want to use to define the media stream.</p>
    pub fn set_fmtp(mut self, input: ::std::option::Option<crate::types::FmtpRequest>) -> Self {
        self.fmtp = input;
        self
    }
    /// <p>The settings that you want to use to define the media stream.</p>
    pub fn get_fmtp(&self) -> &::std::option::Option<crate::types::FmtpRequest> {
        &self.fmtp
    }
    /// <p>The audio language, in a format that is recognized by the receiver.</p>
    pub fn lang(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.lang = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The audio language, in a format that is recognized by the receiver.</p>
    pub fn set_lang(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.lang = input;
        self
    }
    /// <p>The audio language, in a format that is recognized by the receiver.</p>
    pub fn get_lang(&self) -> &::std::option::Option<::std::string::String> {
        &self.lang
    }
    /// Consumes the builder and constructs a [`MediaStreamAttributesRequest`](crate::types::MediaStreamAttributesRequest).
    pub fn build(self) -> crate::types::MediaStreamAttributesRequest {
        crate::types::MediaStreamAttributesRequest {
            fmtp: self.fmtp,
            lang: self.lang,
        }
    }
}
