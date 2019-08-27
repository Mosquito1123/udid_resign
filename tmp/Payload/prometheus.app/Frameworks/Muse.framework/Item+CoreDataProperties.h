//
//  Item+CoreDataProperties.h
//  
//
//  Created by zenox on 2019/5/10.
//
//  This file was automatically generated and should not be edited.
//

#import "Item+CoreDataClass.h"


NS_ASSUME_NONNULL_BEGIN

@interface Item (CoreDataProperties)

+ (NSFetchRequest<Item *> *)fetchRequest;

@property (nullable, nonatomic, copy) NSDate *date;
@property (nonatomic) double duration;
@property (nullable, nonatomic, copy) NSString *extra;
@property (nullable, nonatomic, copy) NSString *name;
@property (nonatomic) int16_t type;
@property (nullable, nonatomic, copy) NSString *value;

@end

NS_ASSUME_NONNULL_END
