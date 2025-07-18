// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// An HTTP Live Streaming (HLS) ingest resource configuration.
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct HlsIngest {
    /// A list of endpoints to which the source stream should be sent.
    pub ingest_endpoints: ::std::option::Option<::std::vec::Vec<crate::types::IngestEndpoint>>,
}
impl HlsIngest {
    /// A list of endpoints to which the source stream should be sent.
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.ingest_endpoints.is_none()`.
    pub fn ingest_endpoints(&self) -> &[crate::types::IngestEndpoint] {
        self.ingest_endpoints.as_deref().unwrap_or_default()
    }
}
impl HlsIngest {
    /// Creates a new builder-style object to manufacture [`HlsIngest`](crate::types::HlsIngest).
    pub fn builder() -> crate::types::builders::HlsIngestBuilder {
        crate::types::builders::HlsIngestBuilder::default()
    }
}

/// A builder for [`HlsIngest`](crate::types::HlsIngest).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct HlsIngestBuilder {
    pub(crate) ingest_endpoints: ::std::option::Option<::std::vec::Vec<crate::types::IngestEndpoint>>,
}
impl HlsIngestBuilder {
    /// Appends an item to `ingest_endpoints`.
    ///
    /// To override the contents of this collection use [`set_ingest_endpoints`](Self::set_ingest_endpoints).
    ///
    /// A list of endpoints to which the source stream should be sent.
    pub fn ingest_endpoints(mut self, input: crate::types::IngestEndpoint) -> Self {
        let mut v = self.ingest_endpoints.unwrap_or_default();
        v.push(input);
        self.ingest_endpoints = ::std::option::Option::Some(v);
        self
    }
    /// A list of endpoints to which the source stream should be sent.
    pub fn set_ingest_endpoints(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::IngestEndpoint>>) -> Self {
        self.ingest_endpoints = input;
        self
    }
    /// A list of endpoints to which the source stream should be sent.
    pub fn get_ingest_endpoints(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::IngestEndpoint>> {
        &self.ingest_endpoints
    }
    /// Consumes the builder and constructs a [`HlsIngest`](crate::types::HlsIngest).
    pub fn build(self) -> crate::types::HlsIngest {
        crate::types::HlsIngest {
            ingest_endpoints: self.ingest_endpoints,
        }
    }
}
