################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../src/aes.c \
../src/memutil.c \
../src/pma.c \
../src/regxp.c \
../src/struitl.c 

OBJS += \
./src/aes.o \
./src/memutil.o \
./src/pma.o \
./src/regxp.o \
./src/struitl.o 

C_DEPS += \
./src/aes.d \
./src/memutil.d \
./src/pma.d \
./src/regxp.d \
./src/struitl.d 


# Each subdirectory must supply rules for building sources it contributes
src/%.o: ../src/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


