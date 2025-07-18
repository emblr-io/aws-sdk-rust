// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents which scan types are automatically enabled for new members of your Amazon Inspector organization.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AutoEnable {
    /// <p>Represents whether Amazon EC2 scans are automatically enabled for new members of your Amazon Inspector organization.</p>
    pub ec2: bool,
    /// <p>Represents whether Amazon ECR scans are automatically enabled for new members of your Amazon Inspector organization.</p>
    pub ecr: bool,
    /// <p>Represents whether Amazon Web Services Lambda standard scans are automatically enabled for new members of your Amazon Inspector organization.</p>
    pub lambda: ::std::option::Option<bool>,
    /// <p>Represents whether Lambda code scans are automatically enabled for new members of your Amazon Inspector organization.</p>
    pub lambda_code: ::std::option::Option<bool>,
    /// <p>Represents whether code repository scans are automatically enabled for new members of your Amazon Inspector organization.</p>
    pub code_repository: ::std::option::Option<bool>,
}
impl AutoEnable {
    /// <p>Represents whether Amazon EC2 scans are automatically enabled for new members of your Amazon Inspector organization.</p>
    pub fn ec2(&self) -> bool {
        self.ec2
    }
    /// <p>Represents whether Amazon ECR scans are automatically enabled for new members of your Amazon Inspector organization.</p>
    pub fn ecr(&self) -> bool {
        self.ecr
    }
    /// <p>Represents whether Amazon Web Services Lambda standard scans are automatically enabled for new members of your Amazon Inspector organization.</p>
    pub fn lambda(&self) -> ::std::option::Option<bool> {
        self.lambda
    }
    /// <p>Represents whether Lambda code scans are automatically enabled for new members of your Amazon Inspector organization.</p>
    pub fn lambda_code(&self) -> ::std::option::Option<bool> {
        self.lambda_code
    }
    /// <p>Represents whether code repository scans are automatically enabled for new members of your Amazon Inspector organization.</p>
    pub fn code_repository(&self) -> ::std::option::Option<bool> {
        self.code_repository
    }
}
impl AutoEnable {
    /// Creates a new builder-style object to manufacture [`AutoEnable`](crate::types::AutoEnable).
    pub fn builder() -> crate::types::builders::AutoEnableBuilder {
        crate::types::builders::AutoEnableBuilder::default()
    }
}

/// A builder for [`AutoEnable`](crate::types::AutoEnable).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AutoEnableBuilder {
    pub(crate) ec2: ::std::option::Option<bool>,
    pub(crate) ecr: ::std::option::Option<bool>,
    pub(crate) lambda: ::std::option::Option<bool>,
    pub(crate) lambda_code: ::std::option::Option<bool>,
    pub(crate) code_repository: ::std::option::Option<bool>,
}
impl AutoEnableBuilder {
    /// <p>Represents whether Amazon EC2 scans are automatically enabled for new members of your Amazon Inspector organization.</p>
    /// This field is required.
    pub fn ec2(mut self, input: bool) -> Self {
        self.ec2 = ::std::option::Option::Some(input);
        self
    }
    /// <p>Represents whether Amazon EC2 scans are automatically enabled for new members of your Amazon Inspector organization.</p>
    pub fn set_ec2(mut self, input: ::std::option::Option<bool>) -> Self {
        self.ec2 = input;
        self
    }
    /// <p>Represents whether Amazon EC2 scans are automatically enabled for new members of your Amazon Inspector organization.</p>
    pub fn get_ec2(&self) -> &::std::option::Option<bool> {
        &self.ec2
    }
    /// <p>Represents whether Amazon ECR scans are automatically enabled for new members of your Amazon Inspector organization.</p>
    /// This field is required.
    pub fn ecr(mut self, input: bool) -> Self {
        self.ecr = ::std::option::Option::Some(input);
        self
    }
    /// <p>Represents whether Amazon ECR scans are automatically enabled for new members of your Amazon Inspector organization.</p>
    pub fn set_ecr(mut self, input: ::std::option::Option<bool>) -> Self {
        self.ecr = input;
        self
    }
    /// <p>Represents whether Amazon ECR scans are automatically enabled for new members of your Amazon Inspector organization.</p>
    pub fn get_ecr(&self) -> &::std::option::Option<bool> {
        &self.ecr
    }
    /// <p>Represents whether Amazon Web Services Lambda standard scans are automatically enabled for new members of your Amazon Inspector organization.</p>
    pub fn lambda(mut self, input: bool) -> Self {
        self.lambda = ::std::option::Option::Some(input);
        self
    }
    /// <p>Represents whether Amazon Web Services Lambda standard scans are automatically enabled for new members of your Amazon Inspector organization.</p>
    pub fn set_lambda(mut self, input: ::std::option::Option<bool>) -> Self {
        self.lambda = input;
        self
    }
    /// <p>Represents whether Amazon Web Services Lambda standard scans are automatically enabled for new members of your Amazon Inspector organization.</p>
    pub fn get_lambda(&self) -> &::std::option::Option<bool> {
        &self.lambda
    }
    /// <p>Represents whether Lambda code scans are automatically enabled for new members of your Amazon Inspector organization.</p>
    pub fn lambda_code(mut self, input: bool) -> Self {
        self.lambda_code = ::std::option::Option::Some(input);
        self
    }
    /// <p>Represents whether Lambda code scans are automatically enabled for new members of your Amazon Inspector organization.</p>
    pub fn set_lambda_code(mut self, input: ::std::option::Option<bool>) -> Self {
        self.lambda_code = input;
        self
    }
    /// <p>Represents whether Lambda code scans are automatically enabled for new members of your Amazon Inspector organization.</p>
    pub fn get_lambda_code(&self) -> &::std::option::Option<bool> {
        &self.lambda_code
    }
    /// <p>Represents whether code repository scans are automatically enabled for new members of your Amazon Inspector organization.</p>
    pub fn code_repository(mut self, input: bool) -> Self {
        self.code_repository = ::std::option::Option::Some(input);
        self
    }
    /// <p>Represents whether code repository scans are automatically enabled for new members of your Amazon Inspector organization.</p>
    pub fn set_code_repository(mut self, input: ::std::option::Option<bool>) -> Self {
        self.code_repository = input;
        self
    }
    /// <p>Represents whether code repository scans are automatically enabled for new members of your Amazon Inspector organization.</p>
    pub fn get_code_repository(&self) -> &::std::option::Option<bool> {
        &self.code_repository
    }
    /// Consumes the builder and constructs a [`AutoEnable`](crate::types::AutoEnable).
    /// This method will fail if any of the following fields are not set:
    /// - [`ec2`](crate::types::builders::AutoEnableBuilder::ec2)
    /// - [`ecr`](crate::types::builders::AutoEnableBuilder::ecr)
    pub fn build(self) -> ::std::result::Result<crate::types::AutoEnable, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::AutoEnable {
            ec2: self.ec2.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "ec2",
                    "ec2 was not specified but it is required when building AutoEnable",
                )
            })?,
            ecr: self.ecr.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "ecr",
                    "ecr was not specified but it is required when building AutoEnable",
                )
            })?,
            lambda: self.lambda,
            lambda_code: self.lambda_code,
            code_repository: self.code_repository,
        })
    }
}
