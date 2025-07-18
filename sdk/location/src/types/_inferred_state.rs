// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The inferred state of the device, given the provided position, IP address, cellular signals, and Wi-Fi- access points.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct InferredState {
    /// <p>The device position inferred by the provided position, IP address, cellular signals, and Wi-Fi- access points.</p>
    pub position: ::std::option::Option<::std::vec::Vec<f64>>,
    /// <p>The level of certainty of the inferred position.</p>
    pub accuracy: ::std::option::Option<crate::types::PositionalAccuracy>,
    /// <p>The distance between the inferred position and the device's self-reported position.</p>
    pub deviation_distance: ::std::option::Option<f64>,
    /// <p>Indicates if a proxy was used.</p>
    pub proxy_detected: bool,
}
impl InferredState {
    /// <p>The device position inferred by the provided position, IP address, cellular signals, and Wi-Fi- access points.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.position.is_none()`.
    pub fn position(&self) -> &[f64] {
        self.position.as_deref().unwrap_or_default()
    }
    /// <p>The level of certainty of the inferred position.</p>
    pub fn accuracy(&self) -> ::std::option::Option<&crate::types::PositionalAccuracy> {
        self.accuracy.as_ref()
    }
    /// <p>The distance between the inferred position and the device's self-reported position.</p>
    pub fn deviation_distance(&self) -> ::std::option::Option<f64> {
        self.deviation_distance
    }
    /// <p>Indicates if a proxy was used.</p>
    pub fn proxy_detected(&self) -> bool {
        self.proxy_detected
    }
}
impl ::std::fmt::Debug for InferredState {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("InferredState");
        formatter.field("position", &"*** Sensitive Data Redacted ***");
        formatter.field("accuracy", &self.accuracy);
        formatter.field("deviation_distance", &self.deviation_distance);
        formatter.field("proxy_detected", &self.proxy_detected);
        formatter.finish()
    }
}
impl InferredState {
    /// Creates a new builder-style object to manufacture [`InferredState`](crate::types::InferredState).
    pub fn builder() -> crate::types::builders::InferredStateBuilder {
        crate::types::builders::InferredStateBuilder::default()
    }
}

/// A builder for [`InferredState`](crate::types::InferredState).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct InferredStateBuilder {
    pub(crate) position: ::std::option::Option<::std::vec::Vec<f64>>,
    pub(crate) accuracy: ::std::option::Option<crate::types::PositionalAccuracy>,
    pub(crate) deviation_distance: ::std::option::Option<f64>,
    pub(crate) proxy_detected: ::std::option::Option<bool>,
}
impl InferredStateBuilder {
    /// Appends an item to `position`.
    ///
    /// To override the contents of this collection use [`set_position`](Self::set_position).
    ///
    /// <p>The device position inferred by the provided position, IP address, cellular signals, and Wi-Fi- access points.</p>
    pub fn position(mut self, input: f64) -> Self {
        let mut v = self.position.unwrap_or_default();
        v.push(input);
        self.position = ::std::option::Option::Some(v);
        self
    }
    /// <p>The device position inferred by the provided position, IP address, cellular signals, and Wi-Fi- access points.</p>
    pub fn set_position(mut self, input: ::std::option::Option<::std::vec::Vec<f64>>) -> Self {
        self.position = input;
        self
    }
    /// <p>The device position inferred by the provided position, IP address, cellular signals, and Wi-Fi- access points.</p>
    pub fn get_position(&self) -> &::std::option::Option<::std::vec::Vec<f64>> {
        &self.position
    }
    /// <p>The level of certainty of the inferred position.</p>
    pub fn accuracy(mut self, input: crate::types::PositionalAccuracy) -> Self {
        self.accuracy = ::std::option::Option::Some(input);
        self
    }
    /// <p>The level of certainty of the inferred position.</p>
    pub fn set_accuracy(mut self, input: ::std::option::Option<crate::types::PositionalAccuracy>) -> Self {
        self.accuracy = input;
        self
    }
    /// <p>The level of certainty of the inferred position.</p>
    pub fn get_accuracy(&self) -> &::std::option::Option<crate::types::PositionalAccuracy> {
        &self.accuracy
    }
    /// <p>The distance between the inferred position and the device's self-reported position.</p>
    pub fn deviation_distance(mut self, input: f64) -> Self {
        self.deviation_distance = ::std::option::Option::Some(input);
        self
    }
    /// <p>The distance between the inferred position and the device's self-reported position.</p>
    pub fn set_deviation_distance(mut self, input: ::std::option::Option<f64>) -> Self {
        self.deviation_distance = input;
        self
    }
    /// <p>The distance between the inferred position and the device's self-reported position.</p>
    pub fn get_deviation_distance(&self) -> &::std::option::Option<f64> {
        &self.deviation_distance
    }
    /// <p>Indicates if a proxy was used.</p>
    /// This field is required.
    pub fn proxy_detected(mut self, input: bool) -> Self {
        self.proxy_detected = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates if a proxy was used.</p>
    pub fn set_proxy_detected(mut self, input: ::std::option::Option<bool>) -> Self {
        self.proxy_detected = input;
        self
    }
    /// <p>Indicates if a proxy was used.</p>
    pub fn get_proxy_detected(&self) -> &::std::option::Option<bool> {
        &self.proxy_detected
    }
    /// Consumes the builder and constructs a [`InferredState`](crate::types::InferredState).
    /// This method will fail if any of the following fields are not set:
    /// - [`proxy_detected`](crate::types::builders::InferredStateBuilder::proxy_detected)
    pub fn build(self) -> ::std::result::Result<crate::types::InferredState, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::InferredState {
            position: self.position,
            accuracy: self.accuracy,
            deviation_distance: self.deviation_distance,
            proxy_detected: self.proxy_detected.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "proxy_detected",
                    "proxy_detected was not specified but it is required when building InferredState",
                )
            })?,
        })
    }
}
impl ::std::fmt::Debug for InferredStateBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("InferredStateBuilder");
        formatter.field("position", &"*** Sensitive Data Redacted ***");
        formatter.field("accuracy", &self.accuracy);
        formatter.field("deviation_distance", &self.deviation_distance);
        formatter.field("proxy_detected", &self.proxy_detected);
        formatter.finish()
    }
}
