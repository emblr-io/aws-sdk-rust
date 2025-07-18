// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An object that recognizes faces or labels in a streaming video. An Amazon Rekognition stream processor is created by a call to <code>CreateStreamProcessor</code>. The request parameters for <code>CreateStreamProcessor</code> describe the Kinesis video stream source for the streaming video, face recognition parameters, and where to stream the analysis resullts.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StreamProcessor {
    /// <p>Name of the Amazon Rekognition stream processor.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>Current status of the Amazon Rekognition stream processor.</p>
    pub status: ::std::option::Option<crate::types::StreamProcessorStatus>,
}
impl StreamProcessor {
    /// <p>Name of the Amazon Rekognition stream processor.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>Current status of the Amazon Rekognition stream processor.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::StreamProcessorStatus> {
        self.status.as_ref()
    }
}
impl StreamProcessor {
    /// Creates a new builder-style object to manufacture [`StreamProcessor`](crate::types::StreamProcessor).
    pub fn builder() -> crate::types::builders::StreamProcessorBuilder {
        crate::types::builders::StreamProcessorBuilder::default()
    }
}

/// A builder for [`StreamProcessor`](crate::types::StreamProcessor).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StreamProcessorBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::StreamProcessorStatus>,
}
impl StreamProcessorBuilder {
    /// <p>Name of the Amazon Rekognition stream processor.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Name of the Amazon Rekognition stream processor.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>Name of the Amazon Rekognition stream processor.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>Current status of the Amazon Rekognition stream processor.</p>
    pub fn status(mut self, input: crate::types::StreamProcessorStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>Current status of the Amazon Rekognition stream processor.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::StreamProcessorStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>Current status of the Amazon Rekognition stream processor.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::StreamProcessorStatus> {
        &self.status
    }
    /// Consumes the builder and constructs a [`StreamProcessor`](crate::types::StreamProcessor).
    pub fn build(self) -> crate::types::StreamProcessor {
        crate::types::StreamProcessor {
            name: self.name,
            status: self.status,
        }
    }
}
