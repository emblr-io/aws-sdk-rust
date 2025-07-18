// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::fmt::Debug)]
pub struct StartMedicalScribeStreamOutput {
    /// <p>The identifier (in UUID format) for your streaming session.</p>
    /// <p>If you already started streaming, this is same ID as the one you specified in your initial <code>StartMedicalScribeStreamRequest</code>.</p>
    pub session_id: ::std::option::Option<::std::string::String>,
    /// <p>The unique identifier for your streaming request.</p>
    pub request_id: ::std::option::Option<::std::string::String>,
    /// <p>The Language Code that you specified in your request. Same as provided in the <code>StartMedicalScribeStreamRequest</code>.</p>
    pub language_code: ::std::option::Option<crate::types::MedicalScribeLanguageCode>,
    /// <p>The sample rate (in hertz) that you specified in your request. Same as provided in the <code>StartMedicalScribeStreamRequest</code></p>
    pub media_sample_rate_hertz: ::std::option::Option<i32>,
    /// <p>The Media Encoding you specified in your request. Same as provided in the <code>StartMedicalScribeStreamRequest</code></p>
    pub media_encoding: ::std::option::Option<crate::types::MedicalScribeMediaEncoding>,
    /// <p>The result stream where you will receive the output events.</p>
    #[cfg_attr(any(feature = "serde-serialize", feature = "serde-deserialize"), serde(skip))]
    pub result_stream:
        crate::event_receiver::EventReceiver<crate::types::MedicalScribeResultStream, crate::types::error::MedicalScribeResultStreamError>,
    _request_id: Option<String>,
}
impl StartMedicalScribeStreamOutput {
    /// <p>The identifier (in UUID format) for your streaming session.</p>
    /// <p>If you already started streaming, this is same ID as the one you specified in your initial <code>StartMedicalScribeStreamRequest</code>.</p>
    pub fn session_id(&self) -> ::std::option::Option<&str> {
        self.session_id.as_deref()
    }
    /// <p>The unique identifier for your streaming request.</p>
    pub fn request_id(&self) -> ::std::option::Option<&str> {
        self.request_id.as_deref()
    }
    /// <p>The Language Code that you specified in your request. Same as provided in the <code>StartMedicalScribeStreamRequest</code>.</p>
    pub fn language_code(&self) -> ::std::option::Option<&crate::types::MedicalScribeLanguageCode> {
        self.language_code.as_ref()
    }
    /// <p>The sample rate (in hertz) that you specified in your request. Same as provided in the <code>StartMedicalScribeStreamRequest</code></p>
    pub fn media_sample_rate_hertz(&self) -> ::std::option::Option<i32> {
        self.media_sample_rate_hertz
    }
    /// <p>The Media Encoding you specified in your request. Same as provided in the <code>StartMedicalScribeStreamRequest</code></p>
    pub fn media_encoding(&self) -> ::std::option::Option<&crate::types::MedicalScribeMediaEncoding> {
        self.media_encoding.as_ref()
    }
    /// <p>The result stream where you will receive the output events.</p>
    pub fn result_stream(
        &self,
    ) -> &crate::event_receiver::EventReceiver<crate::types::MedicalScribeResultStream, crate::types::error::MedicalScribeResultStreamError> {
        &self.result_stream
    }
}
impl ::aws_types::request_id::RequestId for StartMedicalScribeStreamOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl StartMedicalScribeStreamOutput {
    /// Creates a new builder-style object to manufacture [`StartMedicalScribeStreamOutput`](crate::operation::start_medical_scribe_stream::StartMedicalScribeStreamOutput).
    pub fn builder() -> crate::operation::start_medical_scribe_stream::builders::StartMedicalScribeStreamOutputBuilder {
        crate::operation::start_medical_scribe_stream::builders::StartMedicalScribeStreamOutputBuilder::default()
    }
}

/// A builder for [`StartMedicalScribeStreamOutput`](crate::operation::start_medical_scribe_stream::StartMedicalScribeStreamOutput).
#[derive(::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StartMedicalScribeStreamOutputBuilder {
    pub(crate) session_id: ::std::option::Option<::std::string::String>,
    pub(crate) request_id: ::std::option::Option<::std::string::String>,
    pub(crate) language_code: ::std::option::Option<crate::types::MedicalScribeLanguageCode>,
    pub(crate) media_sample_rate_hertz: ::std::option::Option<i32>,
    pub(crate) media_encoding: ::std::option::Option<crate::types::MedicalScribeMediaEncoding>,
    pub(crate) result_stream: ::std::option::Option<
        crate::event_receiver::EventReceiver<crate::types::MedicalScribeResultStream, crate::types::error::MedicalScribeResultStreamError>,
    >,
    _request_id: Option<String>,
}
impl StartMedicalScribeStreamOutputBuilder {
    /// <p>The identifier (in UUID format) for your streaming session.</p>
    /// <p>If you already started streaming, this is same ID as the one you specified in your initial <code>StartMedicalScribeStreamRequest</code>.</p>
    pub fn session_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.session_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier (in UUID format) for your streaming session.</p>
    /// <p>If you already started streaming, this is same ID as the one you specified in your initial <code>StartMedicalScribeStreamRequest</code>.</p>
    pub fn set_session_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.session_id = input;
        self
    }
    /// <p>The identifier (in UUID format) for your streaming session.</p>
    /// <p>If you already started streaming, this is same ID as the one you specified in your initial <code>StartMedicalScribeStreamRequest</code>.</p>
    pub fn get_session_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.session_id
    }
    /// <p>The unique identifier for your streaming request.</p>
    pub fn request_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.request_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for your streaming request.</p>
    pub fn set_request_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.request_id = input;
        self
    }
    /// <p>The unique identifier for your streaming request.</p>
    pub fn get_request_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.request_id
    }
    /// <p>The Language Code that you specified in your request. Same as provided in the <code>StartMedicalScribeStreamRequest</code>.</p>
    pub fn language_code(mut self, input: crate::types::MedicalScribeLanguageCode) -> Self {
        self.language_code = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Language Code that you specified in your request. Same as provided in the <code>StartMedicalScribeStreamRequest</code>.</p>
    pub fn set_language_code(mut self, input: ::std::option::Option<crate::types::MedicalScribeLanguageCode>) -> Self {
        self.language_code = input;
        self
    }
    /// <p>The Language Code that you specified in your request. Same as provided in the <code>StartMedicalScribeStreamRequest</code>.</p>
    pub fn get_language_code(&self) -> &::std::option::Option<crate::types::MedicalScribeLanguageCode> {
        &self.language_code
    }
    /// <p>The sample rate (in hertz) that you specified in your request. Same as provided in the <code>StartMedicalScribeStreamRequest</code></p>
    pub fn media_sample_rate_hertz(mut self, input: i32) -> Self {
        self.media_sample_rate_hertz = ::std::option::Option::Some(input);
        self
    }
    /// <p>The sample rate (in hertz) that you specified in your request. Same as provided in the <code>StartMedicalScribeStreamRequest</code></p>
    pub fn set_media_sample_rate_hertz(mut self, input: ::std::option::Option<i32>) -> Self {
        self.media_sample_rate_hertz = input;
        self
    }
    /// <p>The sample rate (in hertz) that you specified in your request. Same as provided in the <code>StartMedicalScribeStreamRequest</code></p>
    pub fn get_media_sample_rate_hertz(&self) -> &::std::option::Option<i32> {
        &self.media_sample_rate_hertz
    }
    /// <p>The Media Encoding you specified in your request. Same as provided in the <code>StartMedicalScribeStreamRequest</code></p>
    pub fn media_encoding(mut self, input: crate::types::MedicalScribeMediaEncoding) -> Self {
        self.media_encoding = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Media Encoding you specified in your request. Same as provided in the <code>StartMedicalScribeStreamRequest</code></p>
    pub fn set_media_encoding(mut self, input: ::std::option::Option<crate::types::MedicalScribeMediaEncoding>) -> Self {
        self.media_encoding = input;
        self
    }
    /// <p>The Media Encoding you specified in your request. Same as provided in the <code>StartMedicalScribeStreamRequest</code></p>
    pub fn get_media_encoding(&self) -> &::std::option::Option<crate::types::MedicalScribeMediaEncoding> {
        &self.media_encoding
    }
    /// <p>The result stream where you will receive the output events.</p>
    pub fn result_stream(
        mut self,
        input: crate::event_receiver::EventReceiver<crate::types::MedicalScribeResultStream, crate::types::error::MedicalScribeResultStreamError>,
    ) -> Self {
        self.result_stream = ::std::option::Option::Some(input);
        self
    }
    /// <p>The result stream where you will receive the output events.</p>
    pub fn set_result_stream(
        mut self,
        input: ::std::option::Option<
            crate::event_receiver::EventReceiver<crate::types::MedicalScribeResultStream, crate::types::error::MedicalScribeResultStreamError>,
        >,
    ) -> Self {
        self.result_stream = input;
        self
    }
    /// <p>The result stream where you will receive the output events.</p>
    pub fn get_result_stream(
        &self,
    ) -> &::std::option::Option<
        crate::event_receiver::EventReceiver<crate::types::MedicalScribeResultStream, crate::types::error::MedicalScribeResultStreamError>,
    > {
        &self.result_stream
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`StartMedicalScribeStreamOutput`](crate::operation::start_medical_scribe_stream::StartMedicalScribeStreamOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`result_stream`](crate::operation::start_medical_scribe_stream::builders::StartMedicalScribeStreamOutputBuilder::result_stream)
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::start_medical_scribe_stream::StartMedicalScribeStreamOutput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::start_medical_scribe_stream::StartMedicalScribeStreamOutput {
            session_id: self.session_id,
            request_id: self.request_id,
            language_code: self.language_code,
            media_sample_rate_hertz: self.media_sample_rate_hertz,
            media_encoding: self.media_encoding,
            result_stream: self.result_stream.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "result_stream",
                    "result_stream was not specified but it is required when building StartMedicalScribeStreamOutput",
                )
            })?,
            _request_id: self._request_id,
        })
    }
}
