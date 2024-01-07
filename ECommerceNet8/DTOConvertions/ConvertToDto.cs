﻿using ECommerceNet8.DTOs.BaseProductDtos.CustomModels;
using ECommerceNet8.DTOs.ProductVariantDtos.CustomModels;
using ECommerceNet8.DTOs.ShoppingCartDtos.Models;
using ECommerceNet8.Models.ProductModels;
using ECommerceNet8.Models.ShoppingCartModels;

namespace ECommerceNet8.DTOConvertions
{
    public static class ConvertToDto
    {
        public static IEnumerable<Model_BaseProductCustom> ConvertToDtoListCustomProduct(this IEnumerable<BaseProduct> baseProducts)
        {
            var BaseProductCustomReturn = new List<Model_BaseProductCustom>();
            foreach (var baseProduct in baseProducts)
            {
                List<Model_BaseImageCustom> images = new List<Model_BaseImageCustom>();

                foreach(var imageBase in baseProduct.ImageBases)
                {
                    var baseImageCustom = new Model_BaseImageCustom()
                    {
                        Id = imageBase.Id,
                        BaseProductId = imageBase.BaseProductId,
                        AddedOn = imageBase.AddedOn,
                        staticPath = imageBase.StaticPath
                    };
                    images.Add(baseImageCustom);    
                }

                List<Model_ProductVariantCustom> productVariants = new List<Model_ProductVariantCustom>();

                foreach(var productVariant in baseProduct.productVariants)
                {
                    var productColor = new Model_ProductColorCustom()
                    {
                        Id = productVariant.productColor.Id,
                        Name = productVariant.productColor.Name,
                    };

                    var productSize = new Model_ProductSizeCustom()
                    {
                        Id = productVariant.productSize.Id,
                        Name = productVariant.productSize.Name,
                    };

                    var productVariantCustom = new Model_ProductVariantCustom()
                    {
                        Id = productVariant.Id,
                        BaseProductId = productVariant.BaseProductId,
                        productColor = productColor,
                        productSize = productSize,
                        Quantity = productVariant.Quantity
                    };
                    productVariants.Add(productVariantCustom);
                }

                var baseProductCustom = new Model_BaseProductCustom()
                {
                    Id = baseProduct.Id,
                    Name = baseProduct.Name,
                    Description = baseProduct.Description,
                    mainCategory = baseProduct.MainCategory,
                    material = baseProduct.Material,
                    productVariants = productVariants,
                    ImagesBases = images,
                    Price = baseProduct.Price,
                    Discount = baseProduct.Discount,
                    TotalPrice = baseProduct.TotalPrice,
                };
                BaseProductCustomReturn.Add(baseProductCustom);
            }
            return BaseProductCustomReturn;
        }

        public static Model_BaseProductCustom ConvertToDtoCustomProduct(
             this BaseProduct baseProduct)
        {
            var BaseProductCustom = new Model_BaseProductCustom();

            List<Model_BaseImageCustom> images = new List<Model_BaseImageCustom>();

            foreach (var imageBase in baseProduct.ImageBases)
            {
                var imageBaseCustom = new Model_BaseImageCustom()
                {
                    Id = imageBase.Id,
                    BaseProductId = imageBase.BaseProductId,
                    AddedOn = imageBase.AddedOn,
                    staticPath = imageBase.StaticPath
                };

                images.Add(imageBaseCustom);
            }

            List<Model_ProductVariantCustom> productVariants
                = new List<Model_ProductVariantCustom>();

            foreach (var productVariant in baseProduct.productVariants)
            {
                var productColor = new Model_ProductColorCustom()
                {
                    Id = productVariant.productColor.Id,
                    Name = productVariant.productColor.Name
                };

                var productSize = new Model_ProductSizeCustom()
                {
                    Id = productVariant.productSize.Id,
                    Name = productVariant.productSize.Name
                };

                var productVariantCustom = new Model_ProductVariantCustom()
                {
                    Id = productVariant.Id,
                    BaseProductId = productVariant.BaseProductId,
                    productColor = productColor,
                    productSize = productSize,
                    Quantity = productVariant.Quantity
                };

                productVariants.Add(productVariantCustom);
            }

            var baseProductCustom = new Model_BaseProductCustom()
            {
                Id = baseProduct.Id,
                Name = baseProduct.Name,
                Description = baseProduct.Description,
                mainCategory = baseProduct.MainCategory,
                material = baseProduct.Material,
                productVariants = productVariants,
                ImagesBases = images,
                Price = baseProduct.Price,
                Discount = baseProduct.Discount,
                TotalPrice = baseProduct.TotalPrice,
            };

            return baseProductCustom;
        }

        public static Model_BaseProductWithNoExtraInfo ConvertToDtoProductNoInfo(
         this BaseProduct baseProduct)
        {
            var baseProductNoInfo = new Model_BaseProductWithNoExtraInfo()
            {
                Id = baseProduct.Id,
                Name = baseProduct.Name,
                Description = baseProduct.Description,
                MaterialId = baseProduct.MaterialId,
                MainCategoryId = baseProduct.MainCategoryId,
                Price = baseProduct.Price,
                Discount = baseProduct.Discount,
                TotalPrice = baseProduct.TotalPrice
            };

            return baseProductNoInfo;
        }

        public static IEnumerable<Model_ProductVariantReturn> ConvertToDtoProductVariant
            (this IEnumerable<ProductVariant> productVariants)
                {
                    var returnProductVariantCustom = (from productVariant in productVariants
                        select new Model_ProductVariantReturn
                        {
                          Id = productVariant.Id,
                          BaseProductId = productVariant.BaseProductId,
                          productColor = productVariant.productColor,
                          productSize = productVariant.productSize,
                          Quantity = productVariant.Quantity
                        });
            return returnProductVariantCustom;
        }

        public static Model_ProductVariantWithoutObj ConvertToDtoWithoutObj
        (this ProductVariant productVariant)
        {
            var productVariantWithoutObj = new Model_ProductVariantWithoutObj()
            {
                Id = productVariant.Id,
                BaseProductId = productVariant.BaseProductId,
                ProductColorId = productVariant.ProductColorId,
                ProductSizeId = productVariant.ProductSizeId,
                Quantity = productVariant.Quantity
            };

            return productVariantWithoutObj;
        }

        public static Model_ProductVariantReturn ConvertToDtoWithObj
            (this ProductVariant productVariant)
        {
            var productVariantWIthObj = new Model_ProductVariantReturn()
            {
                Id = productVariant.Id,
                BaseProductId = productVariant.BaseProductId,
                productColor = productVariant.productColor,
                productSize = productVariant.productSize,
                Quantity = productVariant.Quantity
            };

            return productVariantWIthObj;
        }

        public static Model_CartItemReturn ConvertToDtoCartItem(
          this BaseProduct baseProduct, ProductVariant productVariant, CartItem cartItem)
        {
            Model_CartItemReturn cartItemReturn = new Model_CartItemReturn();
            bool enoughItems = true;

            if (productVariant.Quantity < cartItem.Quantity)
            {
                enoughItems = false;
            }

            cartItemReturn.BaseProductId = baseProduct.Id;
            cartItemReturn.BaseProductName = baseProduct.Name;
            cartItemReturn.BaseProductDescription = baseProduct.Description;
            cartItemReturn.Price = baseProduct.Price;
            cartItemReturn.Discount = baseProduct.Discount;
            cartItemReturn.TotalPricePerItem = baseProduct.TotalPrice;
            cartItemReturn.ProductVariantId = productVariant.Id;

            Model_ProductColorCustom productColorCustom = new Model_ProductColorCustom()
            {
                Id = productVariant.productColor.Id,
                Name = productVariant.productColor.Name,
            };
            Model_ProductSizeCustom productSizeCustom = new Model_ProductSizeCustom()
            {
                Id = productVariant.productSize.Id,
                Name = productVariant.productSize.Name,
            };

            cartItemReturn.ProductColor = productColorCustom;
            cartItemReturn.ProductSize = productSizeCustom;

            cartItemReturn.AvailableQuantity = productVariant.Quantity;
            cartItemReturn.SelectedQuantity = cartItem.Quantity;
            cartItemReturn.CanBeSold = enoughItems;

            cartItemReturn.TotalPrice = cartItem.Quantity * baseProduct.TotalPrice;

            if (enoughItems)
            {
                cartItemReturn.Message = "Öğe satılabilir";
            }
            else
            {
                cartItemReturn.Message = "Stokta yeterli ürün bulunmamaktadır";
            }

            return cartItemReturn;
        }

    }
}
