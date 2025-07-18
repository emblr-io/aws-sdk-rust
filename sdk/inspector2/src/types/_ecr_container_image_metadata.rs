// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information on the Amazon ECR image metadata associated with a finding.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct EcrContainerImageMetadata {
    /// <p>Tags associated with the Amazon ECR image metadata.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The date an image was last pulled at.</p>
    pub image_pulled_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The last time an Amazon ECR image was used in an Amazon ECS task or Amazon EKS pod.</p>
    pub last_in_use_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The number of Amazon ECS tasks or Amazon EKS pods where the Amazon ECR container image is in use.</p>
    pub in_use_count: ::std::option::Option<i64>,
}
impl EcrContainerImageMetadata {
    /// <p>Tags associated with the Amazon ECR image metadata.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[::std::string::String] {
        self.tags.as_deref().unwrap_or_default()
    }
    /// <p>The date an image was last pulled at.</p>
    pub fn image_pulled_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.image_pulled_at.as_ref()
    }
    /// <p>The last time an Amazon ECR image was used in an Amazon ECS task or Amazon EKS pod.</p>
    pub fn last_in_use_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_in_use_at.as_ref()
    }
    /// <p>The number of Amazon ECS tasks or Amazon EKS pods where the Amazon ECR container image is in use.</p>
    pub fn in_use_count(&self) -> ::std::option::Option<i64> {
        self.in_use_count
    }
}
impl EcrContainerImageMetadata {
    /// Creates a new builder-style object to manufacture [`EcrContainerImageMetadata`](crate::types::EcrContainerImageMetadata).
    pub fn builder() -> crate::types::builders::EcrContainerImageMetadataBuilder {
        crate::types::builders::EcrContainerImageMetadataBuilder::default()
    }
}

/// A builder for [`EcrContainerImageMetadata`](crate::types::EcrContainerImageMetadata).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct EcrContainerImageMetadataBuilder {
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) image_pulled_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) last_in_use_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) in_use_count: ::std::option::Option<i64>,
}
impl EcrContainerImageMetadataBuilder {
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>Tags associated with the Amazon ECR image metadata.</p>
    pub fn tags(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input.into());
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>Tags associated with the Amazon ECR image metadata.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>Tags associated with the Amazon ECR image metadata.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.tags
    }
    /// <p>The date an image was last pulled at.</p>
    pub fn image_pulled_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.image_pulled_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date an image was last pulled at.</p>
    pub fn set_image_pulled_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.image_pulled_at = input;
        self
    }
    /// <p>The date an image was last pulled at.</p>
    pub fn get_image_pulled_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.image_pulled_at
    }
    /// <p>The last time an Amazon ECR image was used in an Amazon ECS task or Amazon EKS pod.</p>
    pub fn last_in_use_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_in_use_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The last time an Amazon ECR image was used in an Amazon ECS task or Amazon EKS pod.</p>
    pub fn set_last_in_use_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_in_use_at = input;
        self
    }
    /// <p>The last time an Amazon ECR image was used in an Amazon ECS task or Amazon EKS pod.</p>
    pub fn get_last_in_use_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_in_use_at
    }
    /// <p>The number of Amazon ECS tasks or Amazon EKS pods where the Amazon ECR container image is in use.</p>
    pub fn in_use_count(mut self, input: i64) -> Self {
        self.in_use_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of Amazon ECS tasks or Amazon EKS pods where the Amazon ECR container image is in use.</p>
    pub fn set_in_use_count(mut self, input: ::std::option::Option<i64>) -> Self {
        self.in_use_count = input;
        self
    }
    /// <p>The number of Amazon ECS tasks or Amazon EKS pods where the Amazon ECR container image is in use.</p>
    pub fn get_in_use_count(&self) -> &::std::option::Option<i64> {
        &self.in_use_count
    }
    /// Consumes the builder and constructs a [`EcrContainerImageMetadata`](crate::types::EcrContainerImageMetadata).
    pub fn build(self) -> crate::types::EcrContainerImageMetadata {
        crate::types::EcrContainerImageMetadata {
            tags: self.tags,
            image_pulled_at: self.image_pulled_at,
            last_in_use_at: self.last_in_use_at,
            in_use_count: self.in_use_count,
        }
    }
}
