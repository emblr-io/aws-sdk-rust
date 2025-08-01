// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A custom label detected in an image by a call to <code>DetectCustomLabels</code>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CustomLabel {
    /// <p>The name of the custom label.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The confidence that the model has in the detection of the custom label. The range is 0-100. A higher value indicates a higher confidence.</p>
    pub confidence: ::std::option::Option<f32>,
    /// <p>The location of the detected object on the image that corresponds to the custom label. Includes an axis aligned coarse bounding box surrounding the object and a finer grain polygon for more accurate spatial information.</p>
    pub geometry: ::std::option::Option<crate::types::Geometry>,
}
impl CustomLabel {
    /// <p>The name of the custom label.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The confidence that the model has in the detection of the custom label. The range is 0-100. A higher value indicates a higher confidence.</p>
    pub fn confidence(&self) -> ::std::option::Option<f32> {
        self.confidence
    }
    /// <p>The location of the detected object on the image that corresponds to the custom label. Includes an axis aligned coarse bounding box surrounding the object and a finer grain polygon for more accurate spatial information.</p>
    pub fn geometry(&self) -> ::std::option::Option<&crate::types::Geometry> {
        self.geometry.as_ref()
    }
}
impl CustomLabel {
    /// Creates a new builder-style object to manufacture [`CustomLabel`](crate::types::CustomLabel).
    pub fn builder() -> crate::types::builders::CustomLabelBuilder {
        crate::types::builders::CustomLabelBuilder::default()
    }
}

/// A builder for [`CustomLabel`](crate::types::CustomLabel).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CustomLabelBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) confidence: ::std::option::Option<f32>,
    pub(crate) geometry: ::std::option::Option<crate::types::Geometry>,
}
impl CustomLabelBuilder {
    /// <p>The name of the custom label.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the custom label.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the custom label.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The confidence that the model has in the detection of the custom label. The range is 0-100. A higher value indicates a higher confidence.</p>
    pub fn confidence(mut self, input: f32) -> Self {
        self.confidence = ::std::option::Option::Some(input);
        self
    }
    /// <p>The confidence that the model has in the detection of the custom label. The range is 0-100. A higher value indicates a higher confidence.</p>
    pub fn set_confidence(mut self, input: ::std::option::Option<f32>) -> Self {
        self.confidence = input;
        self
    }
    /// <p>The confidence that the model has in the detection of the custom label. The range is 0-100. A higher value indicates a higher confidence.</p>
    pub fn get_confidence(&self) -> &::std::option::Option<f32> {
        &self.confidence
    }
    /// <p>The location of the detected object on the image that corresponds to the custom label. Includes an axis aligned coarse bounding box surrounding the object and a finer grain polygon for more accurate spatial information.</p>
    pub fn geometry(mut self, input: crate::types::Geometry) -> Self {
        self.geometry = ::std::option::Option::Some(input);
        self
    }
    /// <p>The location of the detected object on the image that corresponds to the custom label. Includes an axis aligned coarse bounding box surrounding the object and a finer grain polygon for more accurate spatial information.</p>
    pub fn set_geometry(mut self, input: ::std::option::Option<crate::types::Geometry>) -> Self {
        self.geometry = input;
        self
    }
    /// <p>The location of the detected object on the image that corresponds to the custom label. Includes an axis aligned coarse bounding box surrounding the object and a finer grain polygon for more accurate spatial information.</p>
    pub fn get_geometry(&self) -> &::std::option::Option<crate::types::Geometry> {
        &self.geometry
    }
    /// Consumes the builder and constructs a [`CustomLabel`](crate::types::CustomLabel).
    pub fn build(self) -> crate::types::CustomLabel {
        crate::types::CustomLabel {
            name: self.name,
            confidence: self.confidence,
            geometry: self.geometry,
        }
    }
}
