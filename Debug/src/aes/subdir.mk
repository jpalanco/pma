################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../src/aes/rijndael-alg-fst.c \
../src/aes/rijndael-api-fst.c 

OBJS += \
./src/aes/rijndael-alg-fst.o \
./src/aes/rijndael-api-fst.o 

C_DEPS += \
./src/aes/rijndael-alg-fst.d \
./src/aes/rijndael-api-fst.d 


# Each subdirectory must supply rules for building sources it contributes
src/aes/%.o: ../src/aes/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Compiler'
	gcc -DTRACE_KAT_MCT -DINTERMEDIATE_VALUE_KAT -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


