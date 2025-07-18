// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A source file for the input sidecar captions used during the transcoding process.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CaptionSource {
    /// <p>The name of the sidecar caption file that you want Elastic Transcoder to include in the output file.</p>
    pub key: ::std::option::Option<::std::string::String>,
    /// <p>A string that specifies the language of the caption. If you specified multiple inputs with captions, the caption language must match in order to be included in the output. Specify this as one of:</p>
    /// <ul>
    /// <li>
    /// <p>2-character ISO 639-1 code</p></li>
    /// <li>
    /// <p>3-character ISO 639-2 code</p></li>
    /// </ul>
    /// <p>For more information on ISO language codes and language names, see the List of ISO 639-1 codes.</p>
    pub language: ::std::option::Option<::std::string::String>,
    /// <p>For clip generation or captions that do not start at the same time as the associated video file, the <code>TimeOffset</code> tells Elastic Transcoder how much of the video to encode before including captions.</p>
    /// <p>Specify the TimeOffset in the form \[+-\]SS.sss or \[+-\]HH:mm:SS.ss.</p>
    pub time_offset: ::std::option::Option<::std::string::String>,
    /// <p>The label of the caption shown in the player when choosing a language. We recommend that you put the caption language name here, in the language of the captions.</p>
    pub label: ::std::option::Option<::std::string::String>,
    /// <p>The encryption settings, if any, that Elastic Transcoder needs to decyrpt your caption sources, or that you want Elastic Transcoder to apply to your caption sources.</p>
    pub encryption: ::std::option::Option<crate::types::Encryption>,
}
impl CaptionSource {
    /// <p>The name of the sidecar caption file that you want Elastic Transcoder to include in the output file.</p>
    pub fn key(&self) -> ::std::option::Option<&str> {
        self.key.as_deref()
    }
    /// <p>A string that specifies the language of the caption. If you specified multiple inputs with captions, the caption language must match in order to be included in the output. Specify this as one of:</p>
    /// <ul>
    /// <li>
    /// <p>2-character ISO 639-1 code</p></li>
    /// <li>
    /// <p>3-character ISO 639-2 code</p></li>
    /// </ul>
    /// <p>For more information on ISO language codes and language names, see the List of ISO 639-1 codes.</p>
    pub fn language(&self) -> ::std::option::Option<&str> {
        self.language.as_deref()
    }
    /// <p>For clip generation or captions that do not start at the same time as the associated video file, the <code>TimeOffset</code> tells Elastic Transcoder how much of the video to encode before including captions.</p>
    /// <p>Specify the TimeOffset in the form \[+-\]SS.sss or \[+-\]HH:mm:SS.ss.</p>
    pub fn time_offset(&self) -> ::std::option::Option<&str> {
        self.time_offset.as_deref()
    }
    /// <p>The label of the caption shown in the player when choosing a language. We recommend that you put the caption language name here, in the language of the captions.</p>
    pub fn label(&self) -> ::std::option::Option<&str> {
        self.label.as_deref()
    }
    /// <p>The encryption settings, if any, that Elastic Transcoder needs to decyrpt your caption sources, or that you want Elastic Transcoder to apply to your caption sources.</p>
    pub fn encryption(&self) -> ::std::option::Option<&crate::types::Encryption> {
        self.encryption.as_ref()
    }
}
impl CaptionSource {
    /// Creates a new builder-style object to manufacture [`CaptionSource`](crate::types::CaptionSource).
    pub fn builder() -> crate::types::builders::CaptionSourceBuilder {
        crate::types::builders::CaptionSourceBuilder::default()
    }
}

/// A builder for [`CaptionSource`](crate::types::CaptionSource).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CaptionSourceBuilder {
    pub(crate) key: ::std::option::Option<::std::string::String>,
    pub(crate) language: ::std::option::Option<::std::string::String>,
    pub(crate) time_offset: ::std::option::Option<::std::string::String>,
    pub(crate) label: ::std::option::Option<::std::string::String>,
    pub(crate) encryption: ::std::option::Option<crate::types::Encryption>,
}
impl CaptionSourceBuilder {
    /// <p>The name of the sidecar caption file that you want Elastic Transcoder to include in the output file.</p>
    pub fn key(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.key = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the sidecar caption file that you want Elastic Transcoder to include in the output file.</p>
    pub fn set_key(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.key = input;
        self
    }
    /// <p>The name of the sidecar caption file that you want Elastic Transcoder to include in the output file.</p>
    pub fn get_key(&self) -> &::std::option::Option<::std::string::String> {
        &self.key
    }
    /// <p>A string that specifies the language of the caption. If you specified multiple inputs with captions, the caption language must match in order to be included in the output. Specify this as one of:</p>
    /// <ul>
    /// <li>
    /// <p>2-character ISO 639-1 code</p></li>
    /// <li>
    /// <p>3-character ISO 639-2 code</p></li>
    /// </ul>
    /// <p>For more information on ISO language codes and language names, see the List of ISO 639-1 codes.</p>
    pub fn language(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.language = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A string that specifies the language of the caption. If you specified multiple inputs with captions, the caption language must match in order to be included in the output. Specify this as one of:</p>
    /// <ul>
    /// <li>
    /// <p>2-character ISO 639-1 code</p></li>
    /// <li>
    /// <p>3-character ISO 639-2 code</p></li>
    /// </ul>
    /// <p>For more information on ISO language codes and language names, see the List of ISO 639-1 codes.</p>
    pub fn set_language(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.language = input;
        self
    }
    /// <p>A string that specifies the language of the caption. If you specified multiple inputs with captions, the caption language must match in order to be included in the output. Specify this as one of:</p>
    /// <ul>
    /// <li>
    /// <p>2-character ISO 639-1 code</p></li>
    /// <li>
    /// <p>3-character ISO 639-2 code</p></li>
    /// </ul>
    /// <p>For more information on ISO language codes and language names, see the List of ISO 639-1 codes.</p>
    pub fn get_language(&self) -> &::std::option::Option<::std::string::String> {
        &self.language
    }
    /// <p>For clip generation or captions that do not start at the same time as the associated video file, the <code>TimeOffset</code> tells Elastic Transcoder how much of the video to encode before including captions.</p>
    /// <p>Specify the TimeOffset in the form \[+-\]SS.sss or \[+-\]HH:mm:SS.ss.</p>
    pub fn time_offset(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.time_offset = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>For clip generation or captions that do not start at the same time as the associated video file, the <code>TimeOffset</code> tells Elastic Transcoder how much of the video to encode before including captions.</p>
    /// <p>Specify the TimeOffset in the form \[+-\]SS.sss or \[+-\]HH:mm:SS.ss.</p>
    pub fn set_time_offset(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.time_offset = input;
        self
    }
    /// <p>For clip generation or captions that do not start at the same time as the associated video file, the <code>TimeOffset</code> tells Elastic Transcoder how much of the video to encode before including captions.</p>
    /// <p>Specify the TimeOffset in the form \[+-\]SS.sss or \[+-\]HH:mm:SS.ss.</p>
    pub fn get_time_offset(&self) -> &::std::option::Option<::std::string::String> {
        &self.time_offset
    }
    /// <p>The label of the caption shown in the player when choosing a language. We recommend that you put the caption language name here, in the language of the captions.</p>
    pub fn label(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.label = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The label of the caption shown in the player when choosing a language. We recommend that you put the caption language name here, in the language of the captions.</p>
    pub fn set_label(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.label = input;
        self
    }
    /// <p>The label of the caption shown in the player when choosing a language. We recommend that you put the caption language name here, in the language of the captions.</p>
    pub fn get_label(&self) -> &::std::option::Option<::std::string::String> {
        &self.label
    }
    /// <p>The encryption settings, if any, that Elastic Transcoder needs to decyrpt your caption sources, or that you want Elastic Transcoder to apply to your caption sources.</p>
    pub fn encryption(mut self, input: crate::types::Encryption) -> Self {
        self.encryption = ::std::option::Option::Some(input);
        self
    }
    /// <p>The encryption settings, if any, that Elastic Transcoder needs to decyrpt your caption sources, or that you want Elastic Transcoder to apply to your caption sources.</p>
    pub fn set_encryption(mut self, input: ::std::option::Option<crate::types::Encryption>) -> Self {
        self.encryption = input;
        self
    }
    /// <p>The encryption settings, if any, that Elastic Transcoder needs to decyrpt your caption sources, or that you want Elastic Transcoder to apply to your caption sources.</p>
    pub fn get_encryption(&self) -> &::std::option::Option<crate::types::Encryption> {
        &self.encryption
    }
    /// Consumes the builder and constructs a [`CaptionSource`](crate::types::CaptionSource).
    pub fn build(self) -> crate::types::CaptionSource {
        crate::types::CaptionSource {
            key: self.key,
            language: self.language,
            time_offset: self.time_offset,
            label: self.label,
            encryption: self.encryption,
        }
    }
}
