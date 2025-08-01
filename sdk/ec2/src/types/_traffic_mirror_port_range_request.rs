// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about the Traffic Mirror filter rule port range.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TrafficMirrorPortRangeRequest {
    /// <p>The first port in the Traffic Mirror port range. This applies to the TCP and UDP protocols.</p>
    pub from_port: ::std::option::Option<i32>,
    /// <p>The last port in the Traffic Mirror port range. This applies to the TCP and UDP protocols.</p>
    pub to_port: ::std::option::Option<i32>,
}
impl TrafficMirrorPortRangeRequest {
    /// <p>The first port in the Traffic Mirror port range. This applies to the TCP and UDP protocols.</p>
    pub fn from_port(&self) -> ::std::option::Option<i32> {
        self.from_port
    }
    /// <p>The last port in the Traffic Mirror port range. This applies to the TCP and UDP protocols.</p>
    pub fn to_port(&self) -> ::std::option::Option<i32> {
        self.to_port
    }
}
impl TrafficMirrorPortRangeRequest {
    /// Creates a new builder-style object to manufacture [`TrafficMirrorPortRangeRequest`](crate::types::TrafficMirrorPortRangeRequest).
    pub fn builder() -> crate::types::builders::TrafficMirrorPortRangeRequestBuilder {
        crate::types::builders::TrafficMirrorPortRangeRequestBuilder::default()
    }
}

/// A builder for [`TrafficMirrorPortRangeRequest`](crate::types::TrafficMirrorPortRangeRequest).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TrafficMirrorPortRangeRequestBuilder {
    pub(crate) from_port: ::std::option::Option<i32>,
    pub(crate) to_port: ::std::option::Option<i32>,
}
impl TrafficMirrorPortRangeRequestBuilder {
    /// <p>The first port in the Traffic Mirror port range. This applies to the TCP and UDP protocols.</p>
    pub fn from_port(mut self, input: i32) -> Self {
        self.from_port = ::std::option::Option::Some(input);
        self
    }
    /// <p>The first port in the Traffic Mirror port range. This applies to the TCP and UDP protocols.</p>
    pub fn set_from_port(mut self, input: ::std::option::Option<i32>) -> Self {
        self.from_port = input;
        self
    }
    /// <p>The first port in the Traffic Mirror port range. This applies to the TCP and UDP protocols.</p>
    pub fn get_from_port(&self) -> &::std::option::Option<i32> {
        &self.from_port
    }
    /// <p>The last port in the Traffic Mirror port range. This applies to the TCP and UDP protocols.</p>
    pub fn to_port(mut self, input: i32) -> Self {
        self.to_port = ::std::option::Option::Some(input);
        self
    }
    /// <p>The last port in the Traffic Mirror port range. This applies to the TCP and UDP protocols.</p>
    pub fn set_to_port(mut self, input: ::std::option::Option<i32>) -> Self {
        self.to_port = input;
        self
    }
    /// <p>The last port in the Traffic Mirror port range. This applies to the TCP and UDP protocols.</p>
    pub fn get_to_port(&self) -> &::std::option::Option<i32> {
        &self.to_port
    }
    /// Consumes the builder and constructs a [`TrafficMirrorPortRangeRequest`](crate::types::TrafficMirrorPortRangeRequest).
    pub fn build(self) -> crate::types::TrafficMirrorPortRangeRequest {
        crate::types::TrafficMirrorPortRangeRequest {
            from_port: self.from_port,
            to_port: self.to_port,
        }
    }
}
