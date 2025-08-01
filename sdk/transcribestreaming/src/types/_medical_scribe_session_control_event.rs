// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specify the lifecycle of your streaming session.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct MedicalScribeSessionControlEvent {
    /// <p>The type of <code>MedicalScribeSessionControlEvent</code>.</p>
    /// <p>Possible Values:</p>
    /// <ul>
    /// <li>
    /// <p><code>END_OF_SESSION</code> - Indicates the audio streaming is complete. After you send an END_OF_SESSION event, Amazon Web Services HealthScribe starts the post-stream analytics. The session can't be resumed after this event is sent. After Amazon Web Services HealthScribe processes the event, the real-time <code>StreamStatus</code> is <code>COMPLETED</code>. You get the <code>StreamStatus</code> and other stream details with the <a href="https://docs.aws.amazon.com/transcribe/latest/APIReference/API_streaming_GetMedicalScribeStream.html">GetMedicalScribeStream</a> API operation. For more information about different streaming statuses, see the <code>StreamStatus</code> description in the <a href="https://docs.aws.amazon.com/transcribe/latest/APIReference/API_streaming_MedicalScribeStreamDetails.html">MedicalScribeStreamDetails</a>.</p></li>
    /// </ul>
    pub r#type: crate::types::MedicalScribeSessionControlEventType,
}
impl MedicalScribeSessionControlEvent {
    /// <p>The type of <code>MedicalScribeSessionControlEvent</code>.</p>
    /// <p>Possible Values:</p>
    /// <ul>
    /// <li>
    /// <p><code>END_OF_SESSION</code> - Indicates the audio streaming is complete. After you send an END_OF_SESSION event, Amazon Web Services HealthScribe starts the post-stream analytics. The session can't be resumed after this event is sent. After Amazon Web Services HealthScribe processes the event, the real-time <code>StreamStatus</code> is <code>COMPLETED</code>. You get the <code>StreamStatus</code> and other stream details with the <a href="https://docs.aws.amazon.com/transcribe/latest/APIReference/API_streaming_GetMedicalScribeStream.html">GetMedicalScribeStream</a> API operation. For more information about different streaming statuses, see the <code>StreamStatus</code> description in the <a href="https://docs.aws.amazon.com/transcribe/latest/APIReference/API_streaming_MedicalScribeStreamDetails.html">MedicalScribeStreamDetails</a>.</p></li>
    /// </ul>
    pub fn r#type(&self) -> &crate::types::MedicalScribeSessionControlEventType {
        &self.r#type
    }
}
impl MedicalScribeSessionControlEvent {
    /// Creates a new builder-style object to manufacture [`MedicalScribeSessionControlEvent`](crate::types::MedicalScribeSessionControlEvent).
    pub fn builder() -> crate::types::builders::MedicalScribeSessionControlEventBuilder {
        crate::types::builders::MedicalScribeSessionControlEventBuilder::default()
    }
}

/// A builder for [`MedicalScribeSessionControlEvent`](crate::types::MedicalScribeSessionControlEvent).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct MedicalScribeSessionControlEventBuilder {
    pub(crate) r#type: ::std::option::Option<crate::types::MedicalScribeSessionControlEventType>,
}
impl MedicalScribeSessionControlEventBuilder {
    /// <p>The type of <code>MedicalScribeSessionControlEvent</code>.</p>
    /// <p>Possible Values:</p>
    /// <ul>
    /// <li>
    /// <p><code>END_OF_SESSION</code> - Indicates the audio streaming is complete. After you send an END_OF_SESSION event, Amazon Web Services HealthScribe starts the post-stream analytics. The session can't be resumed after this event is sent. After Amazon Web Services HealthScribe processes the event, the real-time <code>StreamStatus</code> is <code>COMPLETED</code>. You get the <code>StreamStatus</code> and other stream details with the <a href="https://docs.aws.amazon.com/transcribe/latest/APIReference/API_streaming_GetMedicalScribeStream.html">GetMedicalScribeStream</a> API operation. For more information about different streaming statuses, see the <code>StreamStatus</code> description in the <a href="https://docs.aws.amazon.com/transcribe/latest/APIReference/API_streaming_MedicalScribeStreamDetails.html">MedicalScribeStreamDetails</a>.</p></li>
    /// </ul>
    /// This field is required.
    pub fn r#type(mut self, input: crate::types::MedicalScribeSessionControlEventType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of <code>MedicalScribeSessionControlEvent</code>.</p>
    /// <p>Possible Values:</p>
    /// <ul>
    /// <li>
    /// <p><code>END_OF_SESSION</code> - Indicates the audio streaming is complete. After you send an END_OF_SESSION event, Amazon Web Services HealthScribe starts the post-stream analytics. The session can't be resumed after this event is sent. After Amazon Web Services HealthScribe processes the event, the real-time <code>StreamStatus</code> is <code>COMPLETED</code>. You get the <code>StreamStatus</code> and other stream details with the <a href="https://docs.aws.amazon.com/transcribe/latest/APIReference/API_streaming_GetMedicalScribeStream.html">GetMedicalScribeStream</a> API operation. For more information about different streaming statuses, see the <code>StreamStatus</code> description in the <a href="https://docs.aws.amazon.com/transcribe/latest/APIReference/API_streaming_MedicalScribeStreamDetails.html">MedicalScribeStreamDetails</a>.</p></li>
    /// </ul>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::MedicalScribeSessionControlEventType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The type of <code>MedicalScribeSessionControlEvent</code>.</p>
    /// <p>Possible Values:</p>
    /// <ul>
    /// <li>
    /// <p><code>END_OF_SESSION</code> - Indicates the audio streaming is complete. After you send an END_OF_SESSION event, Amazon Web Services HealthScribe starts the post-stream analytics. The session can't be resumed after this event is sent. After Amazon Web Services HealthScribe processes the event, the real-time <code>StreamStatus</code> is <code>COMPLETED</code>. You get the <code>StreamStatus</code> and other stream details with the <a href="https://docs.aws.amazon.com/transcribe/latest/APIReference/API_streaming_GetMedicalScribeStream.html">GetMedicalScribeStream</a> API operation. For more information about different streaming statuses, see the <code>StreamStatus</code> description in the <a href="https://docs.aws.amazon.com/transcribe/latest/APIReference/API_streaming_MedicalScribeStreamDetails.html">MedicalScribeStreamDetails</a>.</p></li>
    /// </ul>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::MedicalScribeSessionControlEventType> {
        &self.r#type
    }
    /// Consumes the builder and constructs a [`MedicalScribeSessionControlEvent`](crate::types::MedicalScribeSessionControlEvent).
    /// This method will fail if any of the following fields are not set:
    /// - [`r#type`](crate::types::builders::MedicalScribeSessionControlEventBuilder::type)
    pub fn build(self) -> ::std::result::Result<crate::types::MedicalScribeSessionControlEvent, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::MedicalScribeSessionControlEvent {
            r#type: self.r#type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "r#type",
                    "r#type was not specified but it is required when building MedicalScribeSessionControlEvent",
                )
            })?,
        })
    }
}
